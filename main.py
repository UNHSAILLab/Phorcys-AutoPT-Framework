#Dealing with arguments
# fully reset docker stop $(docker ps -qa) && docker system prune -af --volumes
# sudo tensorboard --logdir=~/ray_results

import argparse, textwrap, logging, configparser, ray, gym
import tensorflow as tf

from ray.rllib import agents
from ray.tune.registry import register_env

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


if __name__ == '__main__':

    tf.get_logger().setLevel('CRITICAL')

    # setup parser 
    config_parser = configparser.ConfigParser()
    config_parser.read('config.ini')

    ip = arguments()
    # setup settings
    print(banner)

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

    env = Environment("xyz", data)

    # may want to disable log_to_driver less output.
    ray.init(logging_level=logging.CRITICAL, log_to_driver=True)

    config = {
        'monitor': True,
        'train_batch_size': 50,
        'framework': 'tf',
        'log_level': 'ERROR'
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
    ray.shutdown()