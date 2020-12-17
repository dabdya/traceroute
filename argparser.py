import argparse


def create_parser():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", dest="timeout", type=float, default=2)
    parser.add_argument("-v", dest="verbose", action="store_true")
    parser.add_argument("-p", dest="port", type=int)
    parser.add_argument("-n", dest="query_nums", type=int, default=15)

    parser.add_argument("IP_ADDRESS")

    subparsers = parser.add_subparsers(dest="proto", required=True)
    subparsers.add_parser("icmp")
    subparsers.add_parser("tcp")
    subparsers.add_parser("udp")

    return parser
