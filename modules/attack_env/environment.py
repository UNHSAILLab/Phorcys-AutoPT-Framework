# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
import gym, logging
import numpy as np
from gym import spaces
from collections import OrderedDict


COST_EXPLOIT = 20.0
COST_SCAN = 10.0

REWARD_SCAN = 50.0
REWARD_EXPLOIT = 1000.0

class Environment(gym.Env):
    """ Custom Environment for Gym Interface """
    # TODO: Convert 2d actions spaces into 1d actions spaces.

    def __init__(self, nettacker_json):
        super(Environment, self).__init__()   

        log_fmt = "[%(levelname)s] [%(asctime)-15s] %(message)s"
        logging.basicConfig(filename='phorcys.log', format=log_fmt, level=logging.DEBUG)

        self.logger = logging.getLogger('Phorcys')

        self.logger.debug(f"JSON FROM Nettacker: {nettacker_json}")

        # create all actions

        # now that we have nettacker_json 
        # create the state space as the observation

        # essentially for each space create a dict.
        self.action_space = spaces.Dict({
            "target": spaces.MultiBinary(5), # change whenever decided will make a class to handle this.
            "port": spaces.Box(low=-1.444, high=1.444, shape=(2,), dtype=np.float32),
            "action": spaces.MultiBinary(5) # will need to change.
        })
    
        # Full state space for observation.
        self.observation_space = spaces.MultiBinary([5,5,5])

        self._construct_network(nettacker_json)


    def _construct_network(self, nettacker_json):

        self.network = OrderedDict()
        # create stateparser

        # get nettacker json and add to stateparser

        address_space = None # need to add refactor

        # once state space code is done can add each host.
        for host in address_space:
            _ports = address_space.get("ports")
            _access_level = address_space.get("access")
            _services = address_space.get("services")

            self.network[host] = {
                "serivces": _services, 
                "ports": _ports, 
                "access_level": _access_level
                # ... more just for now until i get more
            }



    def _check_action_type_cost(self, action):
        # will need to do a translation so (scan if auxillary and exploit if exploit in string)
        if action['type'] == 'scan':
            return COST_SCAN
        elif action['type'] == 'exploit':
            return COST_EXPLOIT
        else:
            raise NotImplementedError


    def _take_action(self, action):
        # return bool success,
        # value if success
        # service information

        target = action['target']
        action = action['action']
        port = action['port']

        # translate first to orginal encoding

        if action['action'] == 'scan':
            # run metasploit module
            raise "Wait for Metasploit integration"
        elif action['action'] == 'exploit':
            raise "Wait for Metasploit integration"
        else: 

        return True, 10, 0.0 # return will be changed once ready

    def step(self, action):
        """ TODO: add step of action"""
        target, action_type = action['target'], action['action']

        action_cost = self._check_action_type_cost(action_type)

        # if not access level
        if self.current_state[target]['access_level'] == [0, 0]:
            return self.current_state, 0 - action_cost, False, {}









    

    def reset(self):
        """
        Reset the state of the environment and returns the initial observation.
        Returns:
            dict obs : the intial observation of the network environment
        """
        self.current_state = self.observation_space.get_initial_state()
        return self.current_state


    def render(self):
        """ TODO: add a render function """
        raise NotImplementedError