import sys

REQUIREMENT_ERROR = -1
INVALID_IP_ERROR = -2
INVALID_PORT_ERROR = -3
NON_POSITIVE_ARG = -4

try:
    from helptools import check_ip, check_port, get_whois
    from argparser import create_parser
    from scapy.all import (
        IP, ICMP, TCP, UDP, DNS, DNSQR, RandShort, send, sr)
except (ImportError, ModuleNotFoundError):
    error = "Requirement modules not found"
    sys.stdout.write(error)
    sys.exit(REQUIREMENT_ERROR)


def check_args(args):
    if not check_ip(args.IP_ADDRESS):
        sys.stdout.write("Invalid IP")
        sys.exit(INVALID_IP_ERROR)

    if args.port and not check_port(args.port):
        sys.stdout.write("Invalid port")
        sys.exit(INVALID_PORT_ERROR)

    non_positive = " should be positive"
    if args.timeout <= 0:
        sys.stdout.write(f"Timeout {non_positive}")
        sys.exit(NON_POSITIVE_ARG)

    if args.query_nums and args.query_nums <= 0:
        sys.stdout.write(f"Query nums {non_positive}")
        sys.exit(NON_POSITIVE_ARG)


def traceroute(target, proto, timeout, max_ttl, port=None):
    packets = {
        "icmp": IP(dst=target, ttl=(1, max_ttl), id=RandShort())
                / ICMP(),
        "tcp": IP(dst=target, ttl=(1, max_ttl), id=RandShort())
               / TCP(flags=0x2),
        "udp": IP(dst=target, ttl=(1, max_ttl), id=RandShort())
               / UDP() / DNS(rd=1, qd=DNSQR(qname="google.com"))
    }

    packet = packets[proto]
    if port:
        packet.dport = port
    ans, _ = sr(packet, timeout=timeout)
    return ans


def main():
    args = create_parser().parse_args()
    check_args(args)
    ans = traceroute(
        args.IP_ADDRESS,
        args.proto,
        args.timeout,
        args.query_nums)

    local_ip = True
    for snd, rcv in ans:
        time = round(rcv.time - snd.time, 5)
        whois = get_whois(str(rcv.src)) if not local_ip else "local"
        print(snd.ttl, rcv.src, time, whois, sep="\t")
        local_ip = False
        if str(rcv.src) == args.IP_ADDRESS:
            break


if __name__ == "__main__":
    main()
