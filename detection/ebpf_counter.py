#!/usr/bin/env python3
"""Bo dem goi bang eBPF/XDP (dung BCC) cho detector - CHI DEM, khong drop. Chi dung trong lab.

Y tuong: gan 1 chuong trinh XDP vao eth0 (trong netns cua victim). XDP ingress chi thay goi
DI VAO victim (inbound) nen tu nhien bo qua goi victim tu tra ve. Chuong trinh dem vao BPF maps:
  - counters[0..3] = packets / syn / ack / udp  (percpu de nhanh, userspace cong lai)
  - src_ips[saddr] = so goi theo IP nguon   -> n_src + H(src)
  - dports[dport]  = so goi theo cong dich (chi TCP, khop ban scapy) -> H(dport)
Luon tra XDP_PASS (detect-only). Userspace doc + XOA maps moi 1 giay.

Can: BCC (python3-bpfcc), kernel headers, quyen CAP_BPF + CAP_NET_ADMIN (xem docker-compose).
"""
import ctypes
import socket
import struct
from collections import Counter

# Chuong trinh eBPF (C, bien dich boi BCC luc chay). VICTIM_IP la hang so (network byte order)
# chen tu userspace; =0 nghia la dem moi goi inbound (khong loc theo dst).
BPF_TEXT = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

BPF_PERCPU_ARRAY(counters, u64, 4);          // 0=packets 1=syn 2=ack 3=udp
BPF_HASH(src_ips, u32, u64, 65536);          // key = saddr (network order)
BPF_HASH(dports,  u16, u64, 65536);          // key = TCP dport (host order)

int xdp_count(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Chi dem goi DI VAO victim (neu VICTIM_IP != 0). XDP ingress von da la inbound.
    if (VICTIM_IP != 0 && ip->daddr != VICTIM_IP) return XDP_PASS;

    u32 saddr = ip->saddr;
    u64 one = 1, *v;
    int k;

    k = 0; v = counters.lookup(&k); if (v) *v += 1;                 // packets (percpu)
    v = src_ips.lookup(&saddr); if (v) lock_xadd(v, 1); else src_ips.update(&saddr, &one);

    if (ip->protocol == IPPROTO_TCP) {
        u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(struct iphdr)) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        u16 dport = ntohs(tcp->dest);
        v = dports.lookup(&dport); if (v) lock_xadd(v, 1); else dports.update(&dport, &one);
        if (tcp->syn) { k = 1; v = counters.lookup(&k); if (v) *v += 1; }
        if (tcp->ack) { k = 2; v = counters.lookup(&k); if (v) *v += 1; }
    } else if (ip->protocol == IPPROTO_UDP) {
        k = 3; v = counters.lookup(&k); if (v) *v += 1;
    }
    return XDP_PASS;
}
"""


class EbpfCounter:
    """Backend dem goi bang XDP, cung interface voi backend scapy: snapshot() + stop()."""

    def __init__(self, iface, victim_ip):
        from bcc import BPF  # import tre: chi can khi dung engine ebpf
        self._BPF = BPF
        self.iface = iface
        # VICTIM_IP: chuyen "a.b.c.d" -> u32 network byte order; rong/None -> 0 (dem tat ca)
        vip = 0
        if victim_ip:
            vip = struct.unpack("I", socket.inet_aton(victim_ip))[0]  # da la network order
        text = BPF_TEXT.replace("VICTIM_IP", str(vip))
        self.b = BPF(text=text)
        fn = self.b.load_func("xdp_count", BPF.XDP)
        # SKB_MODE (generic XDP): chay duoc tren veth khong can driver ho tro native.
        self.flags = BPF.XDP_FLAGS_SKB_MODE
        # go chuong trinh XDP cu (neu lan truoc chet ma chua kip go) roi moi attach, tranh loi "busy".
        try:
            self.b.remove_xdp(iface, self.flags)
        except Exception:
            pass
        self.b.attach_xdp(iface, fn, self.flags)
        self._counters = self.b["counters"]
        self._src = self.b["src_ips"]
        self._dports = self.b["dports"]

    def snapshot(self):
        """Doc + XOA maps cho cua so vua roi. Tra (packets, syn, ack, src_counter, dport_counter)."""
        def total(idx):
            # BPF_PERCPU_ARRAY: moi key tra ve list gia tri tung CPU -> cong lai
            per_cpu = self._counters[ctypes.c_int(idx)]
            return int(sum(x for x in per_cpu))

        packets = total(0)
        syn = total(1)
        ack = total(2)
        # udp = total(3)  # hien chua dung trong luat, giu de mo rong

        src_counter = Counter()
        for k, v in self._src.items():
            src_counter[k.value] = v.value
        dport_counter = Counter()
        for k, v in self._dports.items():
            dport_counter[k.value] = v.value

        # reset cho cua so ke tiep
        self._counters.clear()
        self._src.clear()
        self._dports.clear()
        return packets, syn, ack, src_counter, dport_counter

    def stop(self):
        try:
            self.b.remove_xdp(self.iface, self.flags)
        except Exception:
            pass
