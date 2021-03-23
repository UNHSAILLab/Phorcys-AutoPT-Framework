# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
# R (s', a, s) = value(s', s) - cost(a)

import logging
import pprint
from collections  import OrderedDict
from gym          import Env
from gym          import spaces
from logging      import Logger, basicConfig, getLogger
from typing       import Dict
from .ActionSpace import ActionSpace
from .metasploit  import MetasploitInterface
from .StateSpace  import AccessLevel, ObservationSpace

# Reword Testing Values
COST_EXPLOIT   = 20.0
COST_SCAN      = 10.0
REWARD_EXPLOIT = 1000.0
REWARD_SCAN    = 50.0

class Environment(Env):

    action_space      : spaces.Dict
    observation_space : ObservationSpace
    network           : OrderedDict
    _metasploitAPI    : MetasploitInterface
    _logger           : Logger
    _isVerbose        : bool

    # The Custom Environment Class For The Gym Interface
    def __init__(
            self,
            nettackerJson    : Dict,
            metasploitConfig : Dict,
            isVerbose        : bool = True
    ):
        super(Environment, self).__init__()

        # Configures The Logger For Use
        logFormat = '[%(levelname)s] [%(asctime)-15s] %(message)s'
        basicConfig(filename='phorcys.log', format=logFormat, level=logging.DEBUG)

        # Define And Instantiates The Logger
        self._logger: Logger = getLogger('Phorcys')
        self._logger.debug(f"JSON FROM Nettacker: {nettackerJson}")
        self._isVerbose = isVerbose

        # Instantiates The Action Space, Observation Space, And Network
        self.action_space      : spaces.Dict      = ActionSpace.getActionSpace()
        self.observation_space : ObservationSpace = ObservationSpace()
        self.network           : OrderedDict      = self._construct_network()

        # Sets Up Metasploit API
        self._metasploitAPI = MetasploitInterface(
            metasploitConfig.get('metasploit_ip'),
            metasploitConfig.get('metasploit_port'),
            metasploitConfig.get('metasploit_password')
        )

    # Function That Is Called Periodically To Print A Rendition Of The Environment
    def render(self, mode='human'):
        raise NotImplementedError

    # Resets The State Of The Environment
    def reset(self) -> OrderedDict:
        return self.observation_space.getInitialObvState()

    # Selects And Action To Take And Gets Its Reward
    def step(self, action):
        """ TODO: add step of action"""
        """ return obs, reward, done, info """
        updatedObservation = self._take_action(action)

        # target, action_type = action['target'], action['action']
        # action_cost = self._check_action_type_cost(action_type)
        # if not access level
        # if self.current_state[target]['access_level'] == [0, 0]:
        #     return self.current_state, 0 - action_cost, False, {}

        import random
        return updatedObservation, float(random.randint(-20, 20)), random.randint(-10, 1), {}

    # Gets The Cost Based On The Type Of Action
    def _check_action_type_cost(self, action):
        # will need to do a translation so (scan if auxiliary and exploit if exploit in string)
        if action['type'] == 'scan':
            return COST_SCAN
        elif action['type'] == 'exploit':
            return COST_EXPLOIT
        else:
            raise NotImplementedError

    # Constructs The Network By Getting The Initial Observation Of A Host
    def _construct_network(self) -> OrderedDict:

        # Returns The Initial Observation State
        initialState = self.reset()
        if self._isVerbose: pprint.pprint(list(initialState.items()))
        return initialState

    # When The Agent Takes An Action
    def _take_action(self, action):

        # Parses The Actions From Their Discrete Values
        actions = ActionSpace(action)
        target = actions.getTarget()
        port = actions.getPort()
        exploit = actions.getExploit()

        # Runs The Exploit Chosen By The Agent
        isSuccess, accessLevel, _ = self._metasploitAPI.run(target, exploit, port)
        if isSuccess:
            accessLevelEnum = self.observation_space.getAccessLevel(accessLevel)
            updatedObservation = self.observation_space.updateState(target, accessLevelEnum, port, exploit)
            return updatedObservation
        else:
            return self.observation_space.getObservation(target)