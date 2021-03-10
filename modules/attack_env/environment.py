# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
import gym, logging
import numpy as np
from gym import spaces
from collections import OrderedDict
import pprint 
from .StateSpace import ObservationSpace


COST_EXPLOIT = 20.0
COST_SCAN = 10.0

REWARD_SCAN = 50.0
REWARD_EXPLOIT = 1000.0

class Environment(gym.Env):
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
            "target": spaces.MultiBinary(5), # change whenever decided will make a class to handle this.
            "port": spaces.Box(low=-1.444, high=1.444, shape=(2,), dtype=np.float32),
            "action": spaces.MultiBinary(5) # will need to change.
        })

        # Full state space for observation.
        # TODO ingest nettacker json
        self.observation_space = ObservationSpace()

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
        return self.observation_space.getInitialObvState()


    def render(self):
        """ TODO: add a render function """
        raise NotImplementedError