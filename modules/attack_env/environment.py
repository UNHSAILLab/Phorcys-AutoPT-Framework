# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
# R (s', a, s) = value(s', s) - cost(a)

import gym, logging, pprint
import numpy as np
from gym import spaces
 
from gym.spaces.utils import flatdim
from gym.spaces.utils import flatten_space
from gym.spaces.utils import flatten
from gym.spaces.utils import unflatten

from collections import OrderedDict
from .StateSpace import ObservationSpace


COST_EXPLOIT = 20.0
COST_SCAN = 10.0

REWARD_SCAN = 50.0
REWARD_EXPLOIT = 1000.0

# IMPLEMENT REWARD

class Environment(gym.Env):

    metadata = {'render.modes': ['console']}
    """ Custom Environment for Gym Interface """
    def __init__(self, nettacker_json, verbose=1):
        super(Environment, self).__init__()   

        log_fmt = "[%(levelname)s] [%(asctime)-15s] %(message)s"
        logging.basicConfig(filename='phorcys.log', format=log_fmt, level=logging.DEBUG)

        self.logger = logging.getLogger('Phorcys')

        self.logger.debug(f"JSON FROM Nettacker: {nettacker_json}")
        self.verbose = verbose

        # create all actions

        # now that we have nettacker_json 
        # create the state space as the observation

        # TODO: Fix action space.
        self.action_space = spaces.Dict({
            "target": spaces.Discrete(4), # change whenever decided will make a class to handle this.
            "port": spaces.Discrete(16),
            "action": spaces.Discrete(5) # metasploit module
        })

        # self.action_space = flatten_space(self.action_space)

        # Full state space for observation.
        # TODO ingest nettacker json
        self._observation_space = ObservationSpace()

        self.observation_space = spaces.Dict({
            'accessLevel'     : spaces.MultiBinary([1,3]),
            'hostAddress'     : spaces.MultiBinary([1,4]),
            'openPorts'       : spaces.MultiBinary([1, 16]),
            'services'        : spaces.MultiBinary([1, 4]),
            'vulnerabilities' : spaces.MultiBinary([1, 10])
        })
        
        
        self.network = self._construct_network(self.verbose)


    def _construct_network(self, verbose):
        """ Construct the network based on scan results"""
        inital_state = self.reset()

        if verbose: pprint.pprint(list(inital_state.items()))

        return inital_state


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
            pass 

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
        return self._observation_space.getInitialObvState()


    def render(self):
        """ TODO: add a render function """
        raise NotImplementedError