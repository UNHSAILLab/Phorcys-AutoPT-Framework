# https://towardsdatascience.com/creating-a-custom-openai-gym-environment-for-stock-trading-be532be3910e
# R (s', a, s) = value(s', s) - cost(a)
# part of cost 
# accessLevel

# VPI 
# value of perfect information: 
# essentially mathematical quantification observe news evidence.

# custom scheme evaluating new scheme of
# define generic attack tree and identify a list of types of information 
# that can enhance the ability of an attacker 
# mathematical operation adhoc values of different types of information.

# check difference in access Level
# if same don't add
# reward function for gaining higher level access.

# for now define predefined value for reward for each exploit

import logging, random, pprint

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

    reward_mapping = {
        'auxiliary/scanner/ftp/ftp_version': {
            'cost': 2,
            'success': 5
        },
        'auxiliary/scanner/rdp/rdp_scanner': {
            'cost': 2,
            'success': 5
        },
        'auxiliary/scanner/smb/smb_version': {
            'cost': 2,
            'success': 5
        },
        'auxiliary/scanner/ssh/ssh_version': {
            'cost': 2,
            'success': 5
        },
        'auxiliary/scanner/ftp/anonymous': {
            'cost': 2,
            'success': 10
        },
        'auxiliary/scanner/ftp/ftp_login': {
            'cost': 8,
            'success': 10
        },
        'auxiliary/scanner/rdp/cve_2019_0708_bluekeep': {
            'cost': 5,
            'success': 13
        },
        'auxiliary/scanner/smb/smb_login': {
            'cost': 10,
            'success': 12
        },
        'auxiliary/scanner/smb/smb_ms17_010': {
            'cost': 4,
            'success': 8
        },
        'auxiliary/scanner/ssh/ssh_login': {
            'cost': 8,
            'success': 10
        },
        'exploit/unix/ftp/proftpd_133c_backdoor': {
            'cost': 15,
            'success': 20
        },
        'exploit/windows/rdp/cve_2019_0708_bluekeep_rce': {
            'cost': 20,
            'success': 25
        },
        'exploit/windows/smb/ms17_010_eternalblue': {
            'cost': 23,
            'success': 25
        },
        'exploit/windows/smb/psexec': {
            'cost': 14,
            'success': 20
        }
    }


    # The Custom Environment Class For The Gym Interface
    def __init__(
            self,
            nettackerJson    : Dict,
            metasploitConfig : Dict,
            isVerbose        : bool = True
    ):
        super(Environment, self).__init__()

        random.seed(10)

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
        """ Function used to take an action in the environment
            returns:
                - Observation
                - reward from action executed
                - Terminal state
                - no info 
        """
        # take action
        updatedObservation, exploit, success = self._take_action(action)

        # get reward function
        reward = self._get_reward(exploit, success)

    
        print(f"REWARD: {reward}")
        # check if terminal is met.

        r = random.randint(-2, 5)
        print(f"TERMINAL STATE: {r}")
        return updatedObservation, float(reward), True, {}

    # Gets The Cost Based On The Type Of Action
    def _get_reward(self, exploit, success):

        current_exploit = self.reward_mapping.get(exploit)

        cost = current_exploit.get('cost')
        reward = 0
        if success:
            reward = current_exploit.get('success')

        action_reward = reward - cost

        return action_reward


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
        isSuccess, accessLevel, _ = self._metasploitAPI.run(target=target, exploit=exploit, port=port)

        print(f"accesslevel: {accessLevel}")
        print(f"exploit used: {exploit}")
        print(f"Success: {isSuccess}")

        updatedObservation = self.observation_space.getObservation(target)

        if isSuccess:
            accessLevelEnum = self.observation_space.getAccessLevel(accessLevel)
            updatedObservation = self.observation_space.updateState(target, accessLevelEnum, port, exploit)

        return updatedObservation, exploit, isSuccess