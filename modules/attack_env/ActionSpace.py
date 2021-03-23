import gym.spaces as spaces
from typing import Dict

# Python Class ActionSpace
# Class For Handling Actions Performed By The Agent
# @author Jordan Zimmitti
class ActionSpace:

    # The Action That The Agent Wants To Take
    action: Dict = {}

    # The Id Mapping For The Possible Exploits
    _exploits: Dict[int, str] = {
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

    # The Id Mapping For The Possible Ports
    _ports: Dict[int, int] = {
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

    # The Id Mapping For The Possible Targets
    _targets: Dict[int, str] = {
        0: '192.168.1.100',
        1: '192.168.1.183',
        2: '192.168.1.200',
        3: '192.168.1.201'
    }

    def __init__(
            self,
            action: Dict
    ):
        self.action = action

    # Function That Gets The Action Space Scope
    # @returns {Dict} The action space
    @staticmethod
    def getActionSpace() -> spaces.Dict:

        # The Scope Of The Action Space
        # target  - The host address
        # port    - a port to execute the exploit on
        # exploit - the service or vulnerability to exploit
        return spaces.Dict({
            'target'  : spaces.Discrete(4),
            'port'    : spaces.Discrete(16),
            'exploit' : spaces.Discrete(14)
        })

    # Function That Gets The Exploit From The Action Exploit Id
    # @returns {str} The exploit
    def getExploit(self) -> str:
        exploitId: int = self.action.get('exploit')
        return self._exploits.get(exploitId)

    # Function That Gets The Port From The Action Port Id
    # @returns {int} The port
    def getPort(self) -> int:
        portId: int = self.action.get('port')
        return self._ports.get(portId)

    # Function That Gets The Target Host Address From The Action Target Id
    # @returns {str} The target host address
    def getTarget(self) -> str:
        targetId: int = self.action.get('target')
        return self._targets.get(targetId)

# actionSpace = ActionSpace({'exploit': 9, 'port': 2, 'target': 3})
# print(actionSpace.getTarget())
# print(actionSpace.getPort())
# print(actionSpace.getExploit())