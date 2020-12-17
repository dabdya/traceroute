def check_ip(ip):
    import ipaddress
    try:
        return ipaddress.ip_address(ip)
    except ValueError as error:
        pass


def check_port(port):
    return 0 <= port <= 65535


def get_whois(ip):
    from ipwhois import IPWhois
    return IPWhois(ip).lookup_whois()['asn']
