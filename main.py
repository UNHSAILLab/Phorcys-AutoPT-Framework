#Dealing with arguments

import argparse
import ipaddress
import socket
import configparser
from modules.settings import Config

def arguments():
    parser = argparse.ArgumentParser(description = 'Phorcys Automated Penetration Testing Tool')
    parser.add_argument('-i', type=str, nargs='*', help="Target in IPV4 or IPV6 format)")
    parser.add_argument('-c', type=str, help="Target in CIDR notation")
    parser.add_argument('-d', type=str, nargs='*', help="Target in Domain Name format")
    
    args = parser.parse_args()

    if args.i:
        ip_list = []
        
        try: 
            for ip in args.i:
                if "-" in ip:
                    
                    ip_maxValue = int(ip.split("-")[1])
                   
                    ip_start = ip.split("-")[0]

                    iterative_point = int(ip_start.split(".")[3])

                    for x in range(iterative_point, ip_maxValue+1):
                        address = ".".join(ip_start.split(".")[:3]) + "." + str(x)
                        ipaddress.ip_address(address)
                        ip_list.append(address)
                    
                else:
                    ipaddress.ip_address(ip)
                    ip_list.append(ip)

            return ip_list

        except ValueError:
            print("Invalid IP Address")
            return []

    if args.c:
        cidr_list = args.c
        try:
            return [str(ip) for ip in ipaddress.IPv4Network(cidr_list)]

        except ValueError:
            print("Invalid CIDR Notation")
            return []

    if args.d:
        domain_list = args.d

        try:
            ip_list = []
            for domain in domain_list:
                if "https://" in domain or "http://" in domain:
                    domain = domain.split("//")[1]

                ip_list.append(socket.gethostbyname(domain))
            return ip_list
    
        except socket.gaierror:
            print("Invalid Domain Name")
            return []

if __name__ == '__main__':

    # setup parser 
    config_parser = configparser.ConfigParser()
    config_parser.read('config.ini')

    ip = arguments()

    # setup settings
    settings = {
        'nettacker_ip': config_parser.get('Nettacker', 'ip'), 
        'nettacker_port': config_parser.get('Nettacker', 'port'),
        'nettacker_key': config_parser.get('Nettacker', 'key'),
        'metasploit_ip': config_parser.get('Metasploit', 'ip'),
        'metasploit_port': config_parser.get('Metasploit', 'port'),
        'metasploit_password': config_parser.get('Metasploit', 'password'),
        'target': ip # needs to be a string no more list.
    }
    # create config
    config = Config(**settings)

    print(config.get_dict())

