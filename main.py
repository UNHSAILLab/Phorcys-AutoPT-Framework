#Dealing with arguments
# fully reset docker stop $(docker ps -qa) && docker system prune -af --volumes
# sudo tensorboard --logdir=~/ray_results

import argparse, textwrap, logging, configparser, ray, gym
import tensorflow as tf

import ray.rllib.agents.a3c as A3C
from ray.tune.registry import register_env
from ray import tune


from modules.attack_env import Environment
from modules.settings import Settings
from modules.nettacker import NettackerInterface


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

def arguments():

    parser = argparse.ArgumentParser(
        prog='Phorcys',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(banner)
    )

    parser.add_argument('target', type=str, help="IP Address (IPv4, IPv6, Domain, CIDR)")
    args = parser.parse_args()

    if args.target:
        target = args.target
        return target

    parser.print_help()

def get_config(ip):
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

def config_tf():
    tf.get_logger().setLevel('CRITICAL')
    tf.compat.v1.disable_eager_execution()



def train_agent(data, nettacker_json):

    env = Environment(nettacker_json, data, actionsToTake=5)

    # may want to disable log_to_driver less output.
    ray.shutdown()
    
    #can be security to bind 0.0.0.0 done on purpose to view it.
    ray.init(dashboard_host='0.0.0.0', ignore_reinit_error=True)

    register_env('phorcys', lambda c: env)

    config = A3C.DEFAULT_CONFIG.copy()
    config['env'] = 'phorcys'
    #config['num_gpus'] = 2
    config['num_workers'] = 2
    config['log_level'] = 'DEBUG'
    config['monitor'] = True # write repsidoe stats to log dir ~/ray_results
    config['timesteps_per_iteration'] = 50
    config['min_iter_time_s'] = 0
    config['horizon'] = 50


    #trainer = A3C.A2CTrainer(env='phorcys', config=config)

    tune.run(A3C.A2CTrainer,
        stop={"timesteps_total": 5000},
        config=config,
        checkpoint_freq=10,
        max_failures=5
    )

    ray.shutdown()

    

if __name__ == '__main__':

    config_tf()

    # get scope of assessment
    ip = arguments()
    
    # setup settings
    data = get_config(ip)

    print(banner)

    """
    pp = pprint.PrettyPrinter(indent=4)
    # example
    scanner = NettackerInterface(**data)
    # results = scanner.new_scan()
    pp.pprint(scanner.get_port_scan_data())
    #sleep(10)
    # pp.pprint(scanner.get_scan_data())
    """

    # xyz will be swapped to nettacker after training
    train_agent(data, "xyz")
