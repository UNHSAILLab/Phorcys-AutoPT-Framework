#Dealing with arguments

import argparse
import ipaddress
import socket

def arguments():
    parser = argparse.ArgumentParser(description = 'Phorcys Automated Penetration Testing Tool')
    parser.add_argument('-i', metavar='I', type=str, help="Target in IPV4 or IPV6 format)")
    parser.add_argument('-c', type = str, help="Target in CIDR notation")
    parser.add_argument('-d', type = str, help="Target in Domain Name format")
    
    args = parser.parse_args()

    if args.i:
        IP = args.i
        try:
            ipaddress.ip_address(IP)
            print(IP)
        except Exception:
            print("Invalid IP Address")
    if args.c:
        CIDR = args.c
        try:
            ipaddress.ip_network(CIDR)
            print(CIDR)
        except Exception:
            print("Invalid CIDR Notation or Address")

    if args.d:
        DOMAIN = args.d
        try:
            DATA = socket.gethostbyname(DOMAIN)
            IP_ADDRESS = repr(DATA)
            return IP_ADDRESS
        except Exception:
            print("Invalid Domain Name")
            return False
        
        print(IP_ADDRESS)


if __name__ == '__main__':
    arguments()