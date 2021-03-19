from typing import Dict

# Python Class ActionSpace
# Class For Handling Actions Performed By The Agent
# @author Jordan Zimmitti
class ActionSpace:

    # The Action That The Agent Wants To Take
    action: Dict = {}

    # The Id Mapping For The Possible Exploits
    _exploits: Dict[int, str] = {
        1  : 'auxiliary/scanner/ftp/anonymous',
        2  : 'auxiliary/scanner/ftp/ftp_login',
        3  : 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep',
        4  : 'auxiliary/scanner/smb/smb_login',
        5  : 'auxiliary/scanner/smb/smb_ms17_010',
        6  : 'auxiliary/scanner/ssh/ssh_login',
        7  : 'exploit/unix/ftp/proftpd_133c_backdoor',
        8  : 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
        9  : 'exploit/windows/smb/ms17_010_eternalblue',
        10 : 'exploit/windows/smb/psexec'
    }

    # The Id Mapping For The Possible Ports
    _ports: Dict[int, int] = {
        1  : 21,
        2  : 22,
        3  : 53,
        4  : 80,
        5  : 88,
        6  : 135,
        7  : 139,
        8  : 389,
        9  : 443,
        10 : 445,
        11 : 464,
        12 : 593,
        13 : 636,
        14 : 3268,
        15 : 3269,
        16 : 3389
    }

    # The Id Mapping For The Possible Targets
    _targets: Dict[int, str] = {
        1: '192.168.1.100',
        2: '192.168.1.183',
        3: '192.168.1.200',
        4: '192.168.1.201'
    }

    def __init__(
            self,
            action: Dict
    ):
        self.action = action

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


actionSpace = ActionSpace({'exploit': 9, 'port': 2, 'target': 3})
print(actionSpace.getTarget())
print(actionSpace.getPort())
print(actionSpace.getExploit())