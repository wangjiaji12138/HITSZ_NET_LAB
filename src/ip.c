#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
// 标识字段
static uint16_t global_id = 0;

void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // step1
    if (buf->len < sizeof(ip_hdr_t))
    {
        printf("buf->len < sizeof(ip_hdr_t)\n");
        return;
    }

    // step2
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    int valid = 1;
    valid &= ip_hdr->version == IP_VERSION_4;
    uint16_t total_len = swap16(ip_hdr->total_len16);
    valid &= total_len <= buf->len;
    if (!valid)
    {
        printf("ip_hdr is invalid!\n");
        return;
    }

    // step3
    uint16_t checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    if (checksum != ip_hdr->hdr_checksum16)
    {
        printf("checksum changed from %d to %d !\n", checksum, ip_hdr->hdr_checksum16);
        return;
    }
    else
    {
        printf("checksum is right!\n", checksum, ip_hdr->hdr_checksum16);
        ip_hdr->hdr_checksum16 = checksum;
    }

    // step4
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
    {
        printf("ip_hdr->dst_ip!=net_if_ip\n");
        return;
    }

    // step5
    if (swap16(ip_hdr->total_len16) < buf->len)
    {
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    }

    // step6
    buf_remove_header(buf, sizeof(ip_hdr_t));

    // step7
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) == -1)
    {
        printf("icmp_unreachable\n");
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // step1
    buf_add_header(buf, sizeof(ip_hdr_t));
    // 构造ip头部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->hdr_len = 5;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    ip_hdr->flags_fragment16 = swap16((offset / IP_HDR_OFFSET_PER_BYTE) | (mf ? IP_MORE_FRAGMENT : 0));

    // step2
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));

    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    int this_id = global_id++;
    int offset = 0;
    int mf = 1;
    size_t max_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    if (buf->len > max_len)
    {
        printf("buf->len > ETHERNET_MAX_TRANSPORT_UNIT-sizeof(ip_hdr_t)\n");
        uint16_t buf_len = buf->len;
        while (buf_len > 0)
        {
            buf_t tmp_buf;
            buf_t *ip_buf = &tmp_buf;
            if (buf_len > max_len)
            {
                buf_init(ip_buf, max_len);
                memcpy(ip_buf->data, buf->data, max_len);
                buf_remove_header(buf, max_len);
                buf_len -= max_len;
            }
            else
            {
                mf = 0;
                buf_init(ip_buf, (size_t)buf_len);
                memcpy(ip_buf->data, buf->data, buf_len);
                buf_len -= buf_len;
            }
            ip_fragment_out(ip_buf, ip, protocol, this_id, offset, mf);
            offset += 185;
        }
    }
    else
    {
        ip_fragment_out(buf, ip, protocol, this_id, offset, mf);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}