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

import time
from modules.nettacker import NettackerInterface

import gym, os
import tensorflow as tf

import ray
from ray import tune
from modules.attack_env import Environment
from ray.rllib import agents
from ray.tune.registry import register_env

def arguments():
    banner = """
   ___  __                   
  / _ \/ /  ___  __________ _____
 / ___/ _ \/ _ \/ __/ __/ // (_-<
/_/  /_//_/\___/_/  \__/\_, /___/
                       /___/
    """
    
    parser = argparse.ArgumentParser(description = 'Phorcys Automated Penetration Testing Tool')
    parser.add_argument('target', type=str, help="IP Address (IPv4, IPv6, Domain, CIDR)")
    print(banner)
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
    """
    pp = pprint.PrettyPrinter(indent=4)
    # example
    scanner = NettackerInterface(**data)
    # results = scanner.new_scan()
    pp.pprint(scanner.get_port_scan_data())
    #sleep(10)
    # pp.pprint(scanner.get_scan_data())
    """

    tf.get_logger().setLevel('ERROR')

    env = Environment("xyz", data, isVerbose=False)

    ray.init()

    config = {
        'monitor': True,
        'train_batch_size': 50
    }

    register_env('phorcys', lambda c: env)

    agent = agents.a3c.A2CTrainer(env='phorcys', config=config)

    N_ITER = 20
    s = "{:3d} reward {:6.2f}/{:6.2f}/{:6.2f} len {:6.2f} saved {}"

    for n in range(N_ITER):
        result = agent.train()

        checkpoint = agent.save()
        print("checkpoint saved at", checkpoint)

        print(s.format(
            n + 1,
            result["episode_reward_min"],
            result["episode_reward_mean"],
            result["episode_reward_max"],
            result["episode_len_mean"],
            checkpoint
        ))
    agent.stop()
        # todo if no connection after certain amount of time throw error/ stop execution