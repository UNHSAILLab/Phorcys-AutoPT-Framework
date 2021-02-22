#Dealing with arguments
# fully reset docker stop $(docker ps -qa) && docker system prune -af --volumes

import argparse
import pprint
import configparser
from modules.settings import Settings
import time
from modules.nettacker import NettackerInterface

# from pymetasploit3.msfrpc import MsfRpcClient
# from pymetasploit3.msfconsole import MsfRpcConsole

#['auxiliary', 'encodeformats', 'encoders', 
# 'evasion', 'execute', 'exploits', 'nops', 'payloads', 'platforms', 'post', 'rpc', 'use']    
def dirty_search(client, keyword):
    return [m for m in client.modules.exploits if keyword in m]


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

    data = config.get_dict()

    pp = pprint.PrettyPrinter(indent=4)
    # example
    scanner = NettackerInterface(**data, ping_flag=True)
    # results = scanner.new_scan()
    pp.pprint(scanner.get_port_scan_data())


    #sleep(10)

    # pp.pprint(scanner.get_scan_data())

    # client = MsfRpcClient(data.get('metasploit_password'), port=55552, server=data.get('metasploit_ip'))

    # console_id = client.consoles.console().cid
    # console = client.consoles.console(console_id)
    # console.write("nmap 127.0.0.1")

    # while console.is_busy():
    #     time.sleep(5)
    # print(console.read())

    # method_list = [func for func in dir(console) if callable(getattr(console, func))]
    # print(method_list)