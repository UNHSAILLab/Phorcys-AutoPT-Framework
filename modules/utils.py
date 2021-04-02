import configparser

import tensorflow as tf
from .settings import Settings


  
RED   = "\033[1;31m"  
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"


banner = f"""
{RED}============================================================
{CYAN}\t       ___  __                   
{CYAN}\t      / _ \/ /  ___  __________ _____
{CYAN}\t     / ___/ _ \/ _ \/ __/ __/ // (_-<
{CYAN}\t    /_/  /_//_/\___/_/  \__/\_, /___/
{CYAN}\t                           /___/
                            
{RED}============================================================

{RESET}
Automated Penetration Testing via Deep Reinforcement Learning
"""


def print_banner():
    """ Prints the ASCII Banner Created for Phorcys """
    global banner
    print(banner)
    

def config_tf():
    """ Configuration tensorflow to disable eager execution and don't show redudant information """
    
    tf.get_logger().setLevel('CRITICAL')
    tf.compat.v1.disable_eager_execution()
    
    
def get_config(ip):
    """ Create the configuration dictionary from the settings """
    config_parser = configparser.ConfigParser()

    config_parser.read('config.ini')

    parameters = {
        'nettacker_ip': config_parser.get('Nettacker', 'ip'),
        'nettacker_port': int(config_parser.get('Nettacker', 'port')),
        'nettacker_key': config_parser.get('Nettacker', 'key'),
        'metasploit_ip': config_parser.get('Metasploit', 'ip'),
        'metasploit_port': int(config_parser.get('Metasploit', 'port')),
        'metasploit_password': config_parser.get('Metasploit', 'password'),
        'target': ip
    }

    config = Settings(**parameters)
    return config.get_dict()