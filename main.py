#Dealing with arguments
# see tensorboard.sh
# python3 main.py 192.168.1.100,192.168.1.200,192.168.1.201,192.168.1.183,192.168.1.231,192.168.1.79,192.168.1.115
import os, sys
import tensorflow as tf
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' # remove warnings for normal runs.

import argparse
import textwrap
import pprint
import ray
import ipaddress
# import logging

from ray import tune
import ray.rllib.agents.a3c as A3C
from ray.tune.registry import register_env


import modules.utils as utils
from modules.attack_env import Environment
from modules.nettacker import NettackerInterface
from modules.attack_env.metasploit import MetasploitInterface


def arguments():
    """ Get the IPv4 or CIDR address information of the scope of the assessment """
    
    # set up argparse
    parser = argparse.ArgumentParser(
        prog='Phorcys',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(utils.banner)
    )

    parser.add_argument('target', type=str, help="Scope of the Penetration Test (IPv4 Address or CIDR Notation)")
    parser.add_argument("-s", "--new_scan", dest='scan', action='store_true', 
                        help="Scan with OWASPNettacker or use pre-existing data scan data")
    parser.add_argument("-m", "--mute_banner", dest='banner', action='store_false',
                        help="Hide amazing phorcys banner")

    parser.add_argument("-i", "--iterations", dest='iterations', nargs='?', const=1, type=int,
                        default=1000, help="Define number of training iterations for RL agent (Default: 1000)")
                        
    parser.add_argument("-a", "--actions_per_target", dest='actions', nargs='?', const=1, type=int,
                        default=5, help="Define training number of actions per host that is allowed. (Default: 5)")
  
    parser.add_argument("-l", "--log", dest="logLevel", nargs='?', const=1, type=str, 
                        default='CRITICAL', help="Set the logging level - INFO or DEBUG")
                        
    args = parser.parse_args()

    if not args.logLevel in ['INFO', 'DEBUG', 'CRITICAL']:
        parser.print_help()
        sys.exit(0)
        
        
    if args.target:
        target = args.target
        
        if '/' in args.target:
           result = [str(ip) for ip in ipaddress.IPv4Network(target, False)]
           target = ','.join(result)
        
        return target, args

    parser.print_help()
    
    return None, None

def train_agent(data, nettacker_json, args):
    """ Used for training RL agent for the gym environment via A2C """
    
    env = Environment(nettacker_json, data, actionsToTake=args.actions, logLevel=args.logLevel)

    # may want to disable log_to_driver less output.
    # just to make sure ray is cleaned up before re-enabling.
    ray.shutdown()
    
    # can be security issue to bind 0.0.0.0 done on purpose to view it.
    # just doing for the purpose of analysis
    
    ray.init(dashboard_host='0.0.0.0', ignore_reinit_error=True)

    # register the environment so it is accessible by string name.
    register_env('phorcys', lambda c: env)


    # pull default configuration from ray for A2C/A3C
    config = A3C.DEFAULT_CONFIG.copy()
    
    
    config['env'] = 'phorcys'
    #config['num_gpus'] = 2
    
    # async can do alot of workers
    config['num_workers'] = 2
    
    # verbosity of ray tune
    config['log_level'] = 'DEBUG'
    
    # write to tensorboard
    config['monitor'] = True # write repsidoe stats to log dir ~/ray_results
    
    # do this otherwise it WILL result in halting. Time to wait for all the async workers.
    config['min_iter_time_s'] = 0


    # just use restore to fix it
    tune.run(
        A3C.A2CTrainer,                          # ray rllib
        name="A2C_Train",                        # data set to save in ~/ray_results
        stop={"timesteps_total": args.iterations},    # when to stop training
        config=config,
        checkpoint_freq=1,                       # save after each iterations
        max_failures=5,                          # due to high volattily chances of msfrpc going down for a second are high
                                                 # add this so it doesn't terminate training unless serve error
        checkpoint_at_end=True                   # add checkpoint once done so can continue training.
    )

    ray.shutdown()                           



if __name__ == '__main__':

     
    # disable tensorflow settings
    utils.config_tf()

    # get scope of assessment
    ip, args = arguments()

    # setup settings
    data = utils.get_config(ip)
    
    if args.banner:
        utils.print_banner()

    
    pp = pprint.PrettyPrinter(indent=4)
    scanner = NettackerInterface(**data)
     
    # create a new scan if flagged.
    if args.scan: 
        print('Creating Nettacker scan with targets provided.')
        
        results = scanner.new_scan()
        pp.pprint(results)

    # if args.logLevel:
    #     logging.basicConfig(level=args.logLevel)
    
    # get hosts ports
    nettacker_json = scanner.get_port_scan_data(new_scan=args.scan)
    
    # pp.pprint(nettacker_json)

    try:
        train_agent(data, nettacker_json, args)
    except KeyboardInterrupt:
        ray.shutdown()
