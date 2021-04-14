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

from collections  import OrderedDict
from gym          import Env
from gym          import spaces
from typing       import Dict
from typing       import List 
from .ActionSpace import ActionSpace
from .metasploit  import MetasploitInterface
from modules.report.Report import Report
from .StateSpace  import ObservationSpace

class Environment(Env):

    # When A Host Has No Actions Left To Take
    HOST_MAX_ACTIONS_OUTPUT = 'MAX_TERMINAL'

    # Defines The Cost And Success Reward Values For Each Exploit
    reward_mapping: Dict[str, Dict[str, int]] = {
        'auxiliary/scanner/ftp/ftp_version': {
            'cost'    : 1,
            'success' : 2
        },
        'auxiliary/scanner/rdp/rdp_scanner': {
            'cost'    : 1,
            'success' : 2
        },
        'auxiliary/scanner/smb/smb_version': {
            'cost'    : 1,
            'success' : 2
        },
        'auxiliary/scanner/ssh/ssh_version': {
            'cost'    : 1,
            'success' : 2
        },
        'auxiliary/scanner/ftp/anonymous': {
            'cost'    : 1,
            'success' : 5
        },
        'auxiliary/scanner/ftp/ftp_login': {
            'cost'    : 2,
            'success' : 5
        },
        'auxiliary/scanner/rdp/cve_2019_0708_bluekeep': {
            'cost'    : 2,
            'success' : 5
        },
        'auxiliary/scanner/smb/smb_login': {
            'cost'    : 5,
            'success' : 25
        },
        'auxiliary/scanner/smb/smb_ms17_010': {
            'cost'    : 2,
            'success' : 10
        },
        'auxiliary/scanner/ssh/ssh_login': {
            'cost'    : 5,
            'success' : 25
        },
        'exploit/unix/ftp/proftpd_133c_backdoor': {
            'cost'    : 10,
            'success' : 50
        },
        'exploit/windows/rdp/cve_2019_0708_bluekeep_rce': {
            'cost'    : 10,
            'success' : 60
        },
        'exploit/windows/smb/ms17_010_eternalblue': {
            'cost'    : 10,
            'success' : 65
        }
    }

    # The Custom Environment Class For The Gym Interface
    def __init__(
            self,
            nettackerJson    : List[Dict],
            metasploitConfig : Dict,
            report           : Report,
            actionsToTake    : int  = 20,
            logLevel         : str  = 'ERROR'
    ):
        super(Environment, self).__init__()

        # The Default Amount Of Actions Taken Per Host Before The Agent Terminates
        self.actions_to_take: int = actionsToTake
        self.terminal_dict: Dict[str, int] = {}

        # Sets The Report
        self.report = report

        # Instantiates The Observation Space
        self.observation_space : ObservationSpace = ObservationSpace(nettackerJson)

        # Configures The Action Space
        hostAddressOptions: List[List[str]] = self.observation_space.getStates()[0].getHostAddressOptions()
        self.action_space_instance: ActionSpace = ActionSpace(hostAddressOptions)
        self.action_space: spaces.Dict = self.action_space_instance.resetActionSpace()

        self.metasploitConfig = metasploitConfig
        self.logLevel = logLevel

        # Configures The Metasploit API
        self._metasploitAPI = MetasploitInterface(
            metasploitConfig.get('metasploit_ip'),
            metasploitConfig.get('metasploit_port'),
            metasploitConfig.get('metasploit_password'), 
            logLevel
        )

        self.num_invalid_actions = 0

        # Resets The Environment
        self.reset()

    # Function That Is Called Periodically To Print A Rendition Of The Environment
    def render(self, mode='human'):
        raise NotImplementedError

    # Resets The State Of The Environment
    def reset(self) -> OrderedDict:
        
        self.num_invalid_actions = 0
        # Resets Metasploit
        self._metasploitAPI.reset()

        # Resets The Terminal Dictionary By Getting The Host Addresses From The State
        self.terminal_dict = {}
        for state in self.observation_space.getStates():
            host_address = state.decodeHostAddress()
            self.terminal_dict[host_address] = 0

        # Returns The Initial Observation Space
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
        
        # Gets Whether The Terminal State Has Been Triggered
        isTerminal = self._terminal_state(target)

        # Checks Whether The Chosen Target Has No Actions Left To tTake
        if not isTerminal:
            if output == self.HOST_MAX_ACTIONS_OUTPUT:
                # print(f"DICT: {self.terminal_dict}")
                # print(f"Target: {target}, has taken MAX ACTIONS!")
                # bad action tell it no!

                self.num_invalid_actions = self.num_invalid_actions + 1

                numTerminal = False

                if self.num_invalid_actions >= 5:
                    print('Too many invalid actions hit')
                    numTerminal = True


                return updatedObservation, float(-1), numTerminal, {}

        # When An Exploit Was Successful Update The Report Data
        if isSuccess: self.report.updateReportData(accessLevel, target, port, exploit, output)

        # Gets The Reward Based On The Used Exploit And Its Success
        reward = self._get_reward(exploit, isSuccess)

        if isTerminal:
            print("TERMINAL reached!")

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
        exploit, port, target = self.action_space_instance.getActions(action)

        print(f"Exploit: {exploit} Target: {target}:{port}")

        # Checks Whether A Host Is Already In The Terminal State
        if self._check_host_terminal(target):
            observation = self.observation_space.getObservation(target)
            accessLevel = self.observation_space.getAccessLevel('')

            # Returns The Current Observation And That The Host Has Exceeded The Amount Of Actions It Can Take
            return observation, accessLevel, target, port, exploit, self.HOST_MAX_ACTIONS_OUTPUT, False

        # Runs The Exploit Chosen By The Agent And
        isSuccess, accessLevel, output = self._metasploitAPI.run(target, exploit, port)

        # Updates The Observation If Necessary
        observation = self.observation_space.getObservation(target)
        if isSuccess:
            accessLevelEnum = self.observation_space.getAccessLevel(accessLevel)
            observation = self.observation_space.updateState(target, accessLevelEnum, port, exploit)

        # Returns The Observation Of The Current Target, The Exploit Used, And Whether It Was Successful Or not
        return observation, accessLevel, target, port, exploit, output, isSuccess

    # Checks Whether The Agent Has Triggered The Terminal State
    def _terminal_state(self, target):

        # Adds One To The Amount Of Actions Already Taken On The Current Host
        self.terminal_dict[target] = self.terminal_dict[target] + 1

        # Creates A Temporary List To See If All The Hosts Are Terminal
        hosts_terminal = []

        # Checks Whether Each Host Is Terminal Or Not
        for host in self.terminal_dict:
            if self.terminal_dict[host] >= self.actions_to_take:
                hosts_terminal.append(True)
            else:
                hosts_terminal.append(False)

        # Checks Whether All The Hosts Are Terminal Or Not
        # print(hosts_terminal)
        for isTerminal in hosts_terminal:
            if not isTerminal: return False

        # Returns That The Terminal Condition Was Met
        return True

    # Checks Whether A Host Has Been Terminated
    def _check_host_terminal(self, target):

        # if host is in terminal
        if self.terminal_dict.get(target, 0) >= self.actions_to_take:
            return True

        return False
