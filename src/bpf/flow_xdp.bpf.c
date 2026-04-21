// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "flow_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef always_inline
#define always_inline __attribute__((always_inline)) inline
#endif

/* Ring buffer map untuk kirim event ke user space */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* Hash map cek arah interface */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
} ifdir_map SEC(".maps");

/* Definisi konstanta protokol */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#end
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

/* Helper parsing Ethernet + VLAN */
static always_inline int parse_eth(void **cur, void *end, u16 *h_proto) {
    struct ethhdr *eth = (void *)*cur;
    if ((void *)(eth + 1) > end) return -1;
    *h_proto = bpf_ntohs(eth->h_proto);
    *cur = eth + 1;

    /* handle satu VLAN tag */
    if (*h_proto == ETH_P_8021Q || *h_proto == ETH_P_8021AD) {
        struct vlan_hdr *vh = (void *)*cur;
        if ((void *)(vh + 1) > end) return -1;
        *h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
        *cur = vh + 1;
    }
    return 0;
}

/* Program utama XDP */
SEC("xdp")
int xdp_flow(struct xdp_md *ctx)
{
    /*Read pointer awal & akhir*/
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    void *cur = data;

    __u32 ifindex = ctx->ingress_ifindex;

    /*Parsing ethernet & VLAN*/
    __u16 h_proto;
    if (parse_eth(&cur, data_end, &h_proto) < 0)
        return XDP_PASS;

    struct flow_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return XDP_PASS; /* event drop if buffer penuh */

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->ts_ns   = bpf_ktime_get_ns();
    ev->ifindex = ifindex;
    ev->pkt_len = (__u16)((long)data_end - (long)data);

    /* Lookup direction dari ifdir_map; default = 2 (unknown) */
    __u32 dir_default = 2;
    __u32 *dirp = bpf_map_lookup_elem(&ifdir_map, &ifindex);
    if (dirp)
        ev->direction = *dirp;
    else
        ev->direction = dir_default;

    /* Parsing IPv4 */
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = (void *)cur;
        if ((void *)(ip + 1) > data_end) goto out;
        if (ip->version != 4) goto out;
        __u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(*ip) || (void *)ip + ihl > data_end) goto out;

        ev->ip_version = 4;
        ev->l4_proto   = ip->protocol;
        ev->saddr_v4   = ip->saddr;
        ev->daddr_v4   = ip->daddr;

        cur = (void *)ip + ihl;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)cur;
            if ((void *)(tcp + 1) <= data_end) {
                ev->sport = bpf_ntohs(tcp->source);
                ev->dport = bpf_ntohs(tcp->dest);
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)cur;
            if ((void *)(udp + 1) <= data_end) {
                ev->sport = bpf_ntohs(udp->source);
                ev->dport = bpf_ntohs(udp->dest);
            }
        }
    }

    /* Parsing IPv6 */
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)cur;
        if ((void *)(ip6 + 1) > data_end) goto out;
        if (ip6->version != 6) goto out;

        ev->ip_version = 6;
        ev->l4_proto   = ip6->nexthdr;
        __builtin_memcpy(ev->saddr_v6, &ip6->saddr, sizeof(ip6->saddr));
        __builtin_memcpy(ev->daddr_v6, &ip6->daddr, sizeof(ip6->daddr));

        cur = (void *)(ip6 + 1);

        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp6 = (void *)cur;
            if ((void *)(tcp6 + 1) <= data_end) {
                ev->sport = bpf_ntohs(tcp6->source);
                ev->dport = bpf_ntohs(tcp6->dest);
            }
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp6 = (void *)cur;
            if ((void *)(udp6 + 1) <= data_end) {
                ev->sport = bpf_ntohs(udp6->source);
                ev->dport = bpf_ntohs(udp6->dest);
            }
        }
    }

out:
    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}