#include "ethernet.h"

#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // TO-DO
    // step1
    if(buf->len < sizeof(ether_hdr_t)){
        return;
    }
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    uint16_t protocol = swap16(hdr->protocol16);
    // step2
    buf_remove_header(buf,sizeof(ether_hdr_t));

    // step3
    net_in(buf,protocol,hdr->src);

}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // TO-DO
    // step1
    if(buf->len < ETHERNET_MIN_TRANSPORT_UNIT){
        buf_add_padding(buf,ETHERNET_MIN_TRANSPORT_UNIT-buf->len);
    }
    // step2
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // step3
    memcpy(hdr->dst,mac,NET_MAC_LEN);

    //step4
    memcpy(hdr->src,net_if_mac,NET_MAC_LEN);

    //step5
    hdr->protocol16=swap16(protocol);

    //step6
    driver_send(buf);

}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
