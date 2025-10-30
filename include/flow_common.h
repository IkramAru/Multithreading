#ifndef FLOW_COMMON_H
#define FLOW_COMMON_H

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

/* Event per-paket: user-space bebas agregasi jadi flow */
struct flow_event {
    __u64 packets;         
    __u64 bytes;         
    __u64 ts_ns;         /* waktu paket terakhir diterima*/
    __u32 ifindex;       /* interface asal paket */
    __u8  ip_version;    /* 4 atau 6 */
    __u8  l4_proto;      /* IPPROTO_TCP/UDP/ICMP/... */
    __u16 pkt_len;       /* panjang paket */

    /* IPv4 */
    __u32 saddr_v4;      /* network byte order */
    __u32 daddr_v4;

    /* IPv6 */
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];

    __u16 sport;         /* host byte order jika TCP/UDP, selain itu 0 */
    __u16 dport;

    __u8  direction;     /* 0 = ingress (XDP) */
    __u8  _pad[3];
};

#endif /* FLOW_COMMON_H */
