#Dealing with arguments
# fully reset docker stop $(docker ps -qa) && docker system prune -af --volumes
# sudo tensorboard --logdir=~/ray_results

import argparse, textwrap, logging, ray, gym

import ray.rllib.agents.a3c as A3C
from ray.tune.registry import register_env
from ray import tune


from modules.attack_env import Environment
from modules.nettacker import NettackerInterface
import modules.utils as utils


def arguments():
    """ Get the IPv4 or CIDR address information of the scope of the assessment """
    
    # set up argparse
    parser = argparse.ArgumentParser(
        prog='Phorcys',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(utils.banner)
    )

    parser.add_argument('target', type=str, help="IP Address (IPv4, IPv6, Domain, CIDR)")
    args = parser.parse_args()

    if args.target:
        target = args.target
        return target

    parser.print_help()


def train_agent(data, nettacker_json, actions_to_take=5, iterations=5000):
    """ Used for training RL agent for the gym environment via A2C """
    
    env = Environment(nettacker_json, data, actionsToTake=actions_to_take)

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
        stop={"timesteps_total": iterations},    # when to stop training
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
    ip = arguments()
    
    # setup settings
    data = utils.get_config(ip)
    
    utils.print_banner()

    # TODO: Setup nettacker fully functional with everything else. 
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
