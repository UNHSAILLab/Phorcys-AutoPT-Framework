import copy
import gym.spaces as spaces
from typing import Dict, List
from modules.attack_env.StateSpace import StateSpace

# Python Class ActionSpace
# Class For Handling Actions Performed By The Agent
# @author Jordan Zimmitti
class ActionSpace:

    # When No Host Is Found
    HOST_NOT_FOUND = -1

    # The Agent Action Mapping For The Possible Exploits
    _exploitMapping: Dict[int, str] = {
        0  : 'auxiliary/scanner/ftp/anonymous',
        1  : 'auxiliary/scanner/ftp/ftp_version',
        2  : 'auxiliary/scanner/ftp/ftp_login',
        3  : 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep',
        4  : 'auxiliary/scanner/rdp/rdp_scanner',
        5  : 'auxiliary/scanner/smb/smb_login',
        6  : 'auxiliary/scanner/smb/smb_ms17_010',
        7  : 'auxiliary/scanner/smb/smb_version',
        8  : 'auxiliary/scanner/ssh/ssh_login',
        9  : 'auxiliary/scanner/ssh/ssh_version',
        10 : 'exploit/unix/ftp/proftpd_133c_backdoor',
        11 : 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
        12 : 'exploit/windows/smb/ms17_010_eternalblue',
        13 : 'exploit/windows/smb/psexec'
    }

    # The Agent Action Mapping For The Possible Ports
    _portMapping: Dict[int, int] = {
        0  : 21,
        1  : 22,
        2  : 53,
        3  : 80,
        4  : 88,
        5  : 135,
        6  : 139,
        7  : 389,
        8  : 443,
        9  : 445,
        10 : 464,
        11 : 593,
        12 : 636,
        13 : 3268,
        14 : 3269,
        15 : 3389
    }

    def __init__(
        self,
        hostAddressOptions : List[List[str]]
    ):
        self._targetMapping = self._generateTargetMapping(hostAddressOptions)
        self._defaultTargetMapping = copy.deepcopy(self._targetMapping)

    # Function That Generates The Host Address Mapping To Get The Host That The Agent Is Performing An Action On
    # Returns The host address mapping
    @staticmethod
    def _generateTargetMapping(hostAddressOptions: List[List[str]]):

        # Creates The Empty Mapping Dictionary
        targetMapping: Dict[int, str] = {}

        # Adds The Host Address Target To The Mapping Dictionary
        for index, hostAddressList in enumerate(hostAddressOptions):
            targetMapping[index] = hostAddressList[0]

        # Returns The Target Mapping
        return targetMapping

    # Function That Gets The Action Space Scope
    # @returns {spaces.Dict} The action space
    def _getActionSpace(self) -> spaces.Dict:

        # Gets The Number Of Targets To Choose From
        targetCount: int = len(self._targetMapping)

        # The Scope Of The Action Space
        # target  - The host address
        # port    - a port to execute the exploit on
        # exploit - the service or vulnerability to exploit
        return spaces.Dict({
            'target'  : spaces.Discrete(targetCount),
            'port'    : spaces.Discrete(16),
            'exploit' : spaces.Discrete(14)
        })

    # Function That Gets The Values Associated With The Action That The Agent Has Taken
    # @param {Dict[str, int]} action - The action taken by the agent
    # @return {(str, int, str)} The exploit, port, and target
    def getActions(self, action: Dict[str, int]) -> (str, int, str):

        # Gets The Keys From The Action Taken By The Agent
        exploitKey = action.get('exploit')
        portKey    = action.get('port')
        targetKey  = action.get('target')

        # Gets The Action Values Associated With The Keys
        exploit = self._exploitMapping.get(exploitKey)
        port    = self._portMapping.get(portKey)
        target  = self._targetMapping.get(targetKey)

        # Returns The Exploit, Port, And Target Values
        return exploit, port, target

    # Function That Resets The Action Space
    # @return {spaces.Dict} The initial action space
    def resetActionSpace(self) -> spaces.Dict:
        self._targetMapping = self._defaultTargetMapping
        return self._getActionSpace()

    # Function That Updates The Action Space To Reflect Hosts That Are Terminal And Should Not Be Taken By The Agent
    # @param {str} host - The terminal host that the agent should not be able to take
    # @returns spaces.Dict - The updated
    def updateActionSpace(self, host: str) -> spaces.Dict:

        # Finds The Host That Is Terminal From The Target Mapping
        key = self.HOST_NOT_FOUND
        for currentKey, currentHost in self._targetMapping.items():
            if currentHost == host:
                key = currentKey
                break

        # Returns The Current Action Space When No Host Is Found
        if key == self.HOST_NOT_FOUND:
            return self._getActionSpace()

        # Removes The Host That Is Terminal
        self._targetMapping.pop(key)

        # Update The Keys To Reflect That A Host Was Removed
        targetMapping = {}
        for index, key in enumerate(self._targetMapping):
            targetMapping[index] = self._targetMapping[key]

        # Sets The Updated Target Mapping
        self._targetMapping = targetMapping

        # Returns The Updates Action Space
        return self._getActionSpace()
