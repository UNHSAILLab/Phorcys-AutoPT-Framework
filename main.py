#Dealing with arguments

import argparse
import ipaddress
import socket
import configparser
from modules.settings import Settings

def arguments():
    parser = argparse.ArgumentParser(description = 'Phorcys Automated Penetration Testing Tool')
    parser.add_argument('target', type=str, help="IP Address (IPv4, IPv6, Domain, CIDR)")

    args = parser.parse_args()
    
    if args.target:
        target = args.target
        return target
    
    parser.print_help()

if __name__ == '__main__':

    # setup parser 
    config_parser = configparser.ConfigParser()
    config_parser.read('config.ini')

    ip = arguments()

    # setup settings
    parameters = {
        'nettacker_ip': config_parser.get('Nettacker', 'ip'), 
        'nettacker_port': int(config_parser.get('Nettacker', 'port')),
        'nettacker_key': config_parser.get('Nettacker', 'key'),
        'metasploit_ip': config_parser.get('Metasploit', 'ip'),
        'metasploit_port': int(config_parser.get('Metasploit', 'port')),
        'metasploit_password': config_parser.get('Metasploit', 'password'),
        'target': ip 
    }
    # create config
    config = Settings(**parameters)
    # print(ip)
    print(config.get_dict())