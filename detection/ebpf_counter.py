#!/usr/bin/env python3
"""Bo dem + chan goi bang eBPF/XDP (dung BCC) cho detector. Chi dung trong lab.

DEM (mac dinh): gan XDP vao eth0 (netns victim), dem goi inbound toi victim vao BPF maps:
  - counters[0..4] = packets / syn / ack / udp / blocked
  - src_ips[saddr] = so goi theo IP nguon   -> n_src + H(src)
  - dports[dport]  = so goi theo cong dich (chi TCP) -> H(dport)

CHAN (closed-loop IPS, chi kich hoat khi userspace ghi vao - mac dinh TRO):
  - blocklist[saddr] = expire_ns: neu src bi chan & chua het han -> XDP_DROP (++blocked)
  - token-bucket TOAN CUC theo giao thuc (cfg[0/1/2] = syn/udp/icmp rate pps): drop goi vuot rate.
    Dung cho tan cong SPOOF (SYN/UDP/ICMP) vi per-source vo dung khi moi goi mot IP gia.
Luon DEM TRUOC roi moi chan -> detector van thay dung cuong do tan cong. Khong chan => XDP_PASS.

Can: BCC (python3-bpfcc), kernel headers, CAP_BPF + CAP_NET_ADMIN (xem docker-compose).
"""
import ctypes
import socket
import struct
import time
from collections import Counter

# Chuong trinh eBPF (C). VICTIM_IP la hang so (network byte order) chen tu userspace; 0 = dem tat ca.
BPF_TEXT = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>

BPF_PERCPU_ARRAY(counters, u64, 6);          // 0=packets 1=syn 2=ack 3=udp 4=blocked 5=dns(udp sport 53)
// src_ips bi CHAN kich thuoc o 8192: mot SYN flood spoof (--rand-source) sinh hang chuc nghin
// IP khac nhau/giay; neu de 65536 thi userspace doc+xoa map moi cua so se khung (hang chuc nghin
// syscall) -> detector khung viec in window. Cap 8192 giu readback nhanh; khi day thi update()
// im lang bo qua IP moi, nhung counters[] (packets/syn/ack) van dem DU moi goi -> cuong do van
// chinh xac, chi n_src bao hoa o ~8192 (van ro rang la "rat nhieu nguon" -> DDoS, H~13).
BPF_HASH(src_ips, u32, u64, 8192);           // key = saddr (network order); cap de readback nhanh
BPF_HASH(dports,  u16, u64, 65536);          // key = TCP dport (host order)

// ----- closed-loop IPS (tro neu userspace khong ghi) -----
BPF_HASH(blocklist, u32, u64, 65536);                 // key=saddr, val=expire_ns (bpf_ktime_get_ns)
struct synb_t { struct bpf_spin_lock lock; u64 tokens; u64 last_ns; };
BPF_ARRAY(synb,  struct synb_t, 1);                   // token-bucket SYN toan cuc (nano-token)
BPF_ARRAY(udpb,  struct synb_t, 1);                   // token-bucket UDP toan cuc (xu UDP spoof)
BPF_ARRAY(icmpb, struct synb_t, 1);                   // token-bucket ICMP toan cuc (xu ICMP spoof)
BPF_ARRAY(cfg,   u64, 3);                             // cfg[0]=syn cfg[1]=udp cfg[2]=icmp rate (pps); 0=tat

static __always_inline void bump(int k) {
    u64 *v = counters.lookup(&k); if (v) *v += 1;
}

// token-bucket toan cuc (nano-token, burst = 1 giay). Tra 1 neu phai DROP (het token), 0 = cho qua.
static __always_inline int tb_drop(struct synb_t *s, u64 rate, u64 now) {
    int drop = 0;
    u64 cap = rate * 1000000000ULL;
    bpf_spin_lock(&s->lock);
    if (s->last_ns == 0) { s->last_ns = now; s->tokens = cap; }
    u64 elapsed = now - s->last_ns;
    s->last_ns = now;
    u64 tok = s->tokens + elapsed * rate;                  // moi ns nap (rate) nano-token
    if (tok > cap) tok = cap;
    if (tok >= 1000000000ULL) { tok -= 1000000000ULL; } else { drop = 1; }
    s->tokens = tok;
    bpf_spin_unlock(&s->lock);
    return drop;
}

int xdp_count(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (VICTIM_IP != 0 && ip->daddr != VICTIM_IP) return XDP_PASS;

    u32 saddr = ip->saddr;
    u64 one = 1, *v;

    // ===== DEM TRUOC (giu nguyen hanh vi cu) =====
    bump(0);                                                     // packets
    v = src_ips.lookup(&saddr); if (v) lock_xadd(v, 1); else src_ips.update(&saddr, &one);

    int is_syn = 0, is_udp = 0, is_icmp = 0;
    if (ip->protocol == IPPROTO_TCP) {
        u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(struct iphdr)) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        u16 dport = ntohs(tcp->dest);
        v = dports.lookup(&dport); if (v) lock_xadd(v, 1); else dports.update(&dport, &one);
        if (tcp->syn) { bump(1); is_syn = 1; }
        if (tcp->ack) bump(2);
    } else if (ip->protocol == IPPROTO_UDP) {
        bump(3); is_udp = 1;
        u32 ihl = ip->ihl * 4;
        if (ihl < sizeof(struct iphdr)) return XDP_PASS;
        struct udphdr *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) <= data_end && ntohs(udp->source) == 53) bump(5);  // phan hoi DNS -> DNS amp
    } else if (ip->protocol == IPPROTO_ICMP) {
        is_icmp = 1;
    }

    // ===== ROI MOI CHAN (detect-only neu cac map rong) =====
    u64 now = bpf_ktime_get_ns();

    // (1) blocklist theo nguon
    u64 *exp = blocklist.lookup(&saddr);
    if (exp && now < *exp) { bump(4); return XDP_DROP; }

    // (2) token-bucket toan cuc theo giao thuc: cat goi SPOOF (SYN/UDP/ICMP) vuot rate.
    //     per-source o tren vo dung voi spoof (moi goi mot IP moi) nen phai gioi han theo proto.
    int k0 = 0, k1 = 1, k2 = 2;
    if (is_syn)  { u64 *r = cfg.lookup(&k0); struct synb_t *s = synb.lookup(&k0);
                   if (r && *r > 0 && s && tb_drop(s, *r, now)) { bump(4); return XDP_DROP; } }
    if (is_udp)  { u64 *r = cfg.lookup(&k1); struct synb_t *s = udpb.lookup(&k0);
                   if (r && *r > 0 && s && tb_drop(s, *r, now)) { bump(4); return XDP_DROP; } }
    if (is_icmp) { u64 *r = cfg.lookup(&k2); struct synb_t *s = icmpb.lookup(&k0);
                   if (r && *r > 0 && s && tb_drop(s, *r, now)) { bump(4); return XDP_DROP; } }
    return XDP_PASS;
}
"""


class EbpfCounter:
    """Backend dem (+ chan) bang XDP. Interface dem giong scapy: snapshot() + stop().
    Phan chan (closed-loop) la cac ham phu, chi detector goi khi bat --block."""

    def __init__(self, iface, victim_ip):
        from bcc import BPF  # import tre: chi can khi dung engine ebpf
        self._BPF = BPF
        self.iface = iface
        vip = 0
        if victim_ip:
            vip = struct.unpack("I", socket.inet_aton(victim_ip))[0]  # network order
        text = BPF_TEXT.replace("VICTIM_IP", str(vip))
        self.b = BPF(text=text)
        fn = self.b.load_func("xdp_count", BPF.XDP)
        self.flags = BPF.XDP_FLAGS_SKB_MODE
        try:
            self.b.remove_xdp(iface, self.flags)
        except Exception:
            pass
        self.b.attach_xdp(iface, fn, self.flags)
        self._counters = self.b["counters"]
        self._src = self.b["src_ips"]
        self._dports = self.b["dports"]
        self._blocklist = self.b["blocklist"]
        self._cfg = self.b["cfg"]
        self.last_blocked = 0   # so goi drop trong cua so vua roi (userspace doc tu counters[4])

    def snapshot(self):
        """Doc + XOA maps cho cua so vua roi. Tra (packets, syn, ack, udp, dns, src_counter, dport_counter).
        Dong thoi luu so goi da chan (counters[4]) vao self.last_blocked."""
        def total(idx):
            return int(sum(x for x in self._counters[ctypes.c_int(idx)]))

        packets = total(0)
        syn = total(1)
        ack = total(2)
        udp = total(3)
        self.last_blocked = total(4)
        dns = total(5)

        src_counter = Counter()
        for k, v in self._src.items():
            src_counter[k.value] = v.value
        dport_counter = Counter()
        for k, v in self._dports.items():
            dport_counter[k.value] = v.value

        self._counters.clear()
        self._src.clear()
        self._dports.clear()
        return packets, syn, ack, udp, dns, src_counter, dport_counter

    # ----- closed-loop IPS (chi goi khi --block) -----
    def block_sources(self, src_ints, ttl_s):
        """Chan cac IP nguon (int network-order) voi TTL giay."""
        expire = time.monotonic_ns() + int(ttl_s * 1e9)   # bpf_ktime_get_ns = CLOCK_MONOTONIC
        for ip in src_ints:
            self._blocklist[ctypes.c_uint(ip)] = ctypes.c_ulonglong(expire)

    def expire_blocklist(self):
        """Xoa cac muc het han -> khong chan vinh vien, chan kich thuoc map."""
        now = time.monotonic_ns()
        dead = [k for k, v in self._blocklist.items() if v.value < now]
        for k in dead:
            try:
                del self._blocklist[k]
            except Exception:
                pass

    def clear_blocklist(self):
        """Xoa sach blocklist khi tat phong thu (chuyen ve detect-only)."""
        try:
            self._blocklist.clear()
        except Exception:
            for k in list(self._blocklist.keys()):
                try:
                    del self._blocklist[k]
                except Exception:
                    pass

    def blocked_src_count(self):
        return sum(1 for _ in self._blocklist.items())

    def set_syn_rate(self, rate):
        """Dat rate (pps) cho token-bucket SYN toan cuc (cfg[0]); 0 = tat."""
        self._cfg[ctypes.c_int(0)] = ctypes.c_ulonglong(int(rate))

    def set_udp_rate(self, rate):
        """Dat rate (pps) cho token-bucket UDP toan cuc (cfg[1]); 0 = tat. Xu UDP flood spoof."""
        self._cfg[ctypes.c_int(1)] = ctypes.c_ulonglong(int(rate))

    def set_icmp_rate(self, rate):
        """Dat rate (pps) cho token-bucket ICMP toan cuc (cfg[2]); 0 = tat. Xu ICMP flood spoof."""
        self._cfg[ctypes.c_int(2)] = ctypes.c_ulonglong(int(rate))

    def stop(self):
        try:
            self.b.remove_xdp(self.iface, self.flags)
        except Exception:
            pass
