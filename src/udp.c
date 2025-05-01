#include "udp.h"

#include "icmp.h"
#include "ip.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    // step1
    if (buf->len < sizeof(udp_hdr_t))
    {
        printf("buf->len < sizeof(udp_hdr_t)\n");
        return;
    }
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;

    if (swap16(udp_hdr->total_len16) > buf->len)
    {
        printf("udp_hdr->total_len16 != buf->len \n");
        return;
    }

    // step2
    uint16_t checksum = udp_hdr->checksum16;
    udp_hdr->checksum16 = 0;
    // 伪头部
    udp_hdr->checksum16 = transport_checksum(NET_PROTOCOL_UDP, buf, src_ip, net_if_ip);
    if (udp_hdr->checksum16 != checksum)
    {
        printf("checksum in  \n");
        return;
    }
    // step3
    uint16_t dst_port = swap16(udp_hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port);

    // step4
    if (!handler)
    {
        buf_add_header(buf, sizeof(ip_hdr_t));
        printf("icmp_unreachable \n");
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
    }

    // step5
    else
    {
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(udp_hdr->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    // step1
    buf_add_header(buf, sizeof(udp_hdr_t));

    // step2
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;
    udp_hdr->src_port16 = swap16(src_port);
    udp_hdr->dst_port16 = swap16(dst_port);
    udp_hdr->total_len16 = swap16(buf->len);

    // step3
    udp_hdr->checksum16 = 0;
    udp_hdr->checksum16 = transport_checksum((uint8_t)NET_PROTOCOL_UDP, buf, net_if_ip, dst_ip);

    // step4
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}