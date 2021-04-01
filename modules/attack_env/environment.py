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

import random
import pprint
from collections  import OrderedDict
from gym          import Env
from gym          import spaces
from logging      import Logger, basicConfig, getLogger
from typing       import Dict
from .ActionSpace import ActionSpace
from .metasploit  import MetasploitInterface
from .Report      import Report
from .StateSpace  import AccessLevel, ObservationSpace

class Environment(Env):

    # Defines The Cost And Success Reward Values For Each Exploit
    reward_mapping: Dict[str, Dict[str, int]] = {
        'auxiliary/scanner/ftp/ftp_version': {
            'cost'    : 2,
            'success' : 5
        },
        'auxiliary/scanner/rdp/rdp_scanner': {
            'cost'    : 2,
            'success' : 5
        },
        'auxiliary/scanner/smb/smb_version': {
            'cost'    : 2,
            'success' : 5
        },
        'auxiliary/scanner/ssh/ssh_version': {
            'cost'    : 2,
            'success' : 5
        },
        'auxiliary/scanner/ftp/anonymous': {
            'cost'    : 3,
            'success' : 10
        },
        'auxiliary/scanner/ftp/ftp_login': {
            'cost'    : 2,
            'success' : 10
        },
        'auxiliary/scanner/rdp/cve_2019_0708_bluekeep': {
            'cost'    : 2,
            'success' : 13
        },
        'auxiliary/scanner/smb/smb_login': {
            'cost'    : 2,
            'success' : 12
        },
        'auxiliary/scanner/smb/smb_ms17_010': {
            'cost'    : 2,
            'success' : 8
        },
        'auxiliary/scanner/ssh/ssh_login': {
            'cost'    : 2,
            'success' : 10
        },
        'exploit/unix/ftp/proftpd_133c_backdoor': {
            'cost'    : 5,
            'success' : 20
        },
        'exploit/windows/rdp/cve_2019_0708_bluekeep_rce': {
            'cost'    : 11,
            'success' : 25
        },
        'exploit/windows/smb/ms17_010_eternalblue': {
            'cost'    : 15,
            'success' : 25
        },
        'exploit/windows/smb/psexec': {
            'cost'    : 10,
            'success' : 20
        }
    }

    # The Custom Environment Class For The Gym Interface
    def __init__(
            self,
            nettackerJson    : Dict,
            metasploitConfig : Dict,
            actionsToTake    : int  = 20
    ):
        super(Environment, self).__init__()

        # The Default Amount Of Actions Taken Per Host Before The Agent Terminates
        self.actions_to_take: int = actionsToTake
        self.terminal_dict: Dict[str, int] = {}

        # Instantiates The Reporting Class For Keeping Track Of Data To Show The User
        self.report = Report()

        # Instantiates The Action Space, Observation Space, And Network
        self.action_space      : spaces.Dict      = ActionSpace.getActionSpace()
        self.observation_space : ObservationSpace = ObservationSpace()

        # Variables From Ray Class To Show The Amount Of Steps To Take
        self.spec_max_episode_steps = 50

        # Configures The Metasploit API
        self._metasploitAPI = MetasploitInterface(
            metasploitConfig.get('metasploit_ip'),
            metasploitConfig.get('metasploit_port'),
            metasploitConfig.get('metasploit_password')
        )

        # Resets The Environment
        self.reset()

    # Function That Is Called Periodically To Print A Rendition Of The Environment
    def render(self, mode='human'):
        raise NotImplementedError

    # Resets The State Of The Environment
    def reset(self) -> OrderedDict:
        self.terminal_dict = {}
        return self.observation_space.getInitialObvState()

    # Selects An Action To Take
    def step(self, action):
        """ Function used to take an action in the environment
            returns:
                - Observation
                - reward from action executed
                - Terminal state
                - no info 
        """

        # Gets The Data From The Action That The Agent Has Taken
        updatedObservation, accessLevel, target, port, exploit, output, isSuccess = self._take_action(action)

        # When An Exploit Was Successful Update The Report Data
        if isSuccess: self.report.updateReportData(accessLevel, target, port, exploit, output)

        # Gets The Reward Based On The Used Exploit And Its Success
        reward = self._get_reward(exploit, isSuccess)

        # Gets Whether The Terminal State Has Been Triggered
        isTerminal = self._terminal_state(target, isSuccess)

        # Temporary Printing Of Step Data
        print(f"REWARD: {reward}")
        print(f"ISTERMINAL: {isTerminal}")

        # Returns The Step Back To The Agent
        return updatedObservation, float(reward), isTerminal, {}

    # Gets The Cost Based On The Type Of Action
    def _get_reward(self, exploit, success):

        # Gets The Current Exploit Reward Dictionary Based On The Exploit Used By The Agent
        current_exploit = self.reward_mapping.get(exploit)

        # Gets The Cost Of Using The Chosen Exploit
        cost = current_exploit.get('cost')

        # When The Exploit Is Successful Get The Reward
        reward = 0
        if success: reward = current_exploit.get('success')

        # Returns The Overall Reward For The Chosen Action
        return reward - cost

    # When The Agent Takes An Action
    def _take_action(self, action):

        # Parses The Actions From Their Discrete Values
        actions = ActionSpace(action)
        target  = actions.getTarget()
        port    = actions.getPort()
        exploit = actions.getExploit()

        # Runs The Exploit Chosen By The Agent And
        isSuccess, accessLevel, output = self._metasploitAPI.run(target=target, exploit=exploit, port=port)

        # Updates The Observation If Necessary
        observation = self.observation_space.getObservation(target)
        if isSuccess:
            accessLevelEnum = self.observation_space.getAccessLevel(accessLevel)
            observation = self.observation_space.updateState(target, accessLevelEnum, port, exploit)

        # Returns The Observation Of The Current Target, The Exploit Used, And Whether It Was Successful Or not
        return observation, accessLevel, target, port, exploit, output, isSuccess

    # Checks Whether The Agent Has Triggered The Terminal State
    def _terminal_state(self, target, isSuccess):

        # Temporary Printing Of Terminal State Data
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(self.terminal_dict)

        # Sets The Default Amount Of Actions When The Target Does Not Exist
        self.terminal_dict.setdefault(target, 0)

        # When The Action Was Successful
        if isSuccess:

            # Allows The Agent To Take Five More Actions On The Current Target
            self.terminal_dict[target] = self.terminal_dict[target] - 5
            return False

        # Adds One To The Amount Of Actions Already Taken On The Current Host
        self.terminal_dict[target] = self.terminal_dict[target] + 1

        # When The Max Amount Of Actions Were Taken, Terminate
        if self.terminal_dict[target] >= self.actions_to_take:
            print("TERMINATED!!!!!!!!!!!!!!!!!!!")
            return True

        # Continue Taking Actions
        return False
