# Dealing with arguments
# see tensorboard.sh
# nohup python3 main.py 192.168.1.100,192.168.1.200,192.168.1.201,192.168.1.183,192.168.1.231,192.168.1.79,192.168.1.115 -j temp.json -a 7 -w 20 > a2c_train.log &
# ray start --head --num-cpus=48


import os, sys
import logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '4' # remove warnings for normal runs.

import tensorflow as tf
logging.getLogger('tensorflow').disabled = True
tf.compat.v1.disable_resource_variables()
import argparse
import textwrap
import pprint
import json
import ray
import ipaddress
from ray import tune
import ray.rllib.agents.a3c as A3C
from ray.tune.registry import register_env
from ray.tune.logger import pretty_print

import modules.utils as utils
from modules.attack_env import Environment
from modules.nettacker import NettackerInterface
from modules.attack_env.metasploit import MetasploitInterface
from modules.report.Report import Report


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

    parser.add_argument('-j', "--json_file", dest='json', type=str, nargs='?', const=1, 
                        default='', help="use json file instead of nettacker data.")

    parser.add_argument("-i", "--iterations", dest='iterations', nargs='?', const=1, type=int,
                        default=5000, help="Define number of training iterations for RL agent (Default: 5000)")

    parser.add_argument("-a", "--actions_per_target", dest='actions', nargs='?', const=1, type=int,
                        default=5, help="Define training number of actions per host that is allowed. (Default: 5)")

    parser.add_argument("-w", "--workers", dest="workers", nargs='?', const=1, type=int,
                        default=0, help="Define number of Workers for training.")

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

def train_agent(data, nettacker_json, report, args):
    """ Used for training RL agent for the gym environment via A2C """

    env = Environment(nettacker_json, data, report, actionsToTake=args.actions, logLevel=args.logLevel)

    # print(env.step({'target'  : 1, 'port'    : 2,  'exploit' : 3}))

    # states = env.observation_space.getStates()

    # report.addStateDataToReport(states)

    # return

    # may want to disable log_to_driver less output.
    # just to make sure ray is cleaned up before re-enabling.
    ray.shutdown()

    # can be security issue to bind 0.0.0.0 done on purpose to view it.
    # just doing for the purpose of analysis
    """log_to_driver=False,"""  
    ray.init(dashboard_host='0.0.0.0', configure_logging=False, logging_level=100, ignore_reinit_error=True, num_cpus=32)

    # register the environment so it is accessible by string name.
    register_env('phorcys', lambda c: env)


    # pull default configuration from ray for A2C/A3C
    config = A3C.DEFAULT_CONFIG.copy()

    config['env'] = 'phorcys'
    # config['monitor'] = True # write repsidoe stats to log dir ~/ray_results

    print(f"NUM WORKERS: {args.workers}")
    config['num_workers'] = args.workers

    # do this otherwise it WILL result in halting. Time to wait for all the async workers.
    config['min_iter_time_s'] = 10 # least 10 seconds before collection - shouldn't hit but good idea.
    config['train_batch_size'] = 64
    config["microbatch_size"] = 16
    config['min_iter_time_s'] = 20
    config['batch_mode'] = 'truncate_episodes'
    config['log_level'] = 'ERROR'
    config['framework'] = 'tfe'
    config['timesteps_per_iteration'] = 200

    # just use restore to fix it
    tune.run(
        A3C.A2CTrainer,                                 # ray rllib                        # data set to save in ~/ray_results
        stop={"episodes_total": args.iterations},       # when to stop training
        config=config,
        checkpoint_freq=5,                              # save after each iterations
        max_failures=100,                               # due to high volattily chances of msfrpc going down for a second are high
        # use resume to resume experiment with the directory of checkpoint
        #name="Phorcys_A2C_Trial",
        # resume="~/ray_results/A2C_2021-04-21_10-37-56/A2C_phorcys_29aba_00000_0_2021-04-21_10-37-56/checkpoint_95/checkpoint-95",
        # restore='/home/szuro1/ray_results/A2C_2021-04-23_10-50-40/A2C_phorcys_45977_00000_0_2021-04-23_10-50-40/checkpoint_291/checkpoint-291',
        checkpoint_at_end=True                   # add checkpoint once done so can continue training.

    )

    ray.shutdown()

    # setup report information
    states = env.observation_space.getStates()

    report.addStateDataToReport(states)

def use_model(data, nettacker_json, report, args):

    

    report: Report = Report()

    env = Environment(nettacker_json, data, report, actionsToTake=args.actions, logLevel=args.logLevel)

    ray.shutdown()

    # can be security issue to bind 0.0.0.0 done on purpose to view it.
    # just doing for the purpose of analysis
    """log_to_driver=False,"""  
    ray.init(dashboard_host='0.0.0.0', configure_logging=False, logging_level=100, ignore_reinit_error=True, num_cpus=32)

    # register the environment so it is accessible by string name.
    register_env('phorcys', lambda c: env)

    config = A3C.DEFAULT_CONFIG.copy()

    config['env'] = 'phorcys'
    config['num_workers'] = 1
    # config['monitor'] = True # write repsidoe stats to log dir ~/ray_results

    # do this otherwise it WILL result in halting. Time to wait for all the async workers.
    config['min_iter_time_s'] = 10 # least 10 seconds before collection - shouldn't hit but good idea.
    config['train_batch_size'] = 64
    config["microbatch_size"] = 16
    # config["explore"] = False
    config['min_iter_time_s'] = 20
    config['batch_mode'] = 'truncate_episodes'
    config['log_level'] = 'ERROR'
    config['framework'] = 'tfe'
    config['timesteps_per_iteration'] = 200


    agent = A3C.A2CTrainer(config=config)
    agent.restore("/home/szuro1/ray_results/A2C_2021-04-16_15-49-02/A2C_phorcys_cb5b5_00000_0_2021-04-16_15-49-02/checkpoint_150/checkpoint-150")

    policy = agent.workers.local_worker().get_policy()
    image = f"{dir_path}/images/phorcys_cropped.png"

    epi_reward = 0
    done = False
    obs = env.reset()

    while not done:
        action = agent.compute_action(obs)
        obs, reward, done, info = env.step(action)
        epi_reward += reward

    print(f"REWARD: {epi_reward}")

    states = env.observation_space.getStates()
    pprint.pprint(states)

    report.addStateDataToReport(states)

    image = f"{dir_path}/images/phorcys_cropped.png"

    report.generateReport(image)


if __name__ == '__main__':

    # disable tensorflow settings
    # utils.config_tf()

    # get scope of assessment
    ip, args = arguments()

    dir_path = os.path.dirname(os.path.realpath(__file__))
    # setup settings
    data = utils.get_config(ip, dir_path)

    if args.banner:
        utils.print_banner()

    pp = pprint.PrettyPrinter(indent=4)
    scanner = NettackerInterface(**data)

    # create a new scan if flagged.
    nettacker_json = None

    # check if to use from json
    if args.json == '':
        
        # create new scan
        if args.scan: 
            print('Creating Nettacker scan with targets provided.')
            
            results = scanner.new_scan()
            pp.pprint(results)
        
        nettacker_json = scanner.get_port_scan_data(new_scan=args.scan)

        # write to file for future usage
        with open('temp.json', 'w') as json_file:
            json.dump(nettacker_json, json_file, indent=4)

    else:
        # using json file.
        print(f"Using Json file: {args.json}")
        with open(args.json) as json_file:
            nettacker_json = json.load(json_file)

    
    try:
        # Instantiates The Report Class
        report: Report = Report()
        train_agent(data, nettacker_json, report, args)

        # use_model(data, nettacker_json, report, args)
        image = f"{dir_path}/images/phorcys_cropped.png"

        # report.generateReport(image)
    except KeyboardInterrupt:
        ray.shutdown()
