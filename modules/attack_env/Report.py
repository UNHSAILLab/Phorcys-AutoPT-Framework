from typing import Dict
from .StateSpace import AccessLevel

class Report:

    # Initializes The Report Class
    def __init__(self):

        # The Dictionary Of Hosts With Found Vulnerabilities Based On Their Ports
        self.hosts: Dict[str, Dict] = {}

    # Function That Updates The Report Data When A Vulnerability Is Found Successful
    # @param {AccessLevel} accessLevel - The access level for a single host that the agent was able to obtain
    # @param {str}         host        - The unique host address
    # @param {int}         port        - The port number that the vulnerability was found on
    # @param {str}         exploit     - The vulnerability found
    # @param {str}         output      - The data from the vulnerability that was found
    def updateReportData(self, accessLevel: AccessLevel, host: str, port: int, exploit: str, output: str):

        # When The Host Does Not Exist
        if host not in self.hosts:

            # Saves The Vulnerability Data
            self.hosts[host] = {
                port: {
                    'accessLevel' : accessLevel,
                    'exploit'     : [exploit],
                    'output'      : [output]
                }
            }
            return

        # When The Port Does Not Exist
        if port not in self.hosts[host]:

            # Saves The Vulnerability Data
            self.hosts[host][port] = {
                'accessLevel': accessLevel,
                'exploit': [exploit],
                'output': [output]
            }
            return

        # Updates The Access Level When The Current Access Level Is Higher Than The Saved Access Level
        savedAccessLevel = self.hosts[host][port].get('accessLevel')
        if savedAccessLevel != AccessLevel.ADMIN_ACCESS:
            if savedAccessLevel == AccessLevel.USER_ACCESS:
                if accessLevel == AccessLevel.ADMIN_ACCESS:
                    self.hosts[host][port]['accessLevel'] = accessLevel
            if savedAccessLevel == AccessLevel.NO_ACCESS:
                if accessLevel == AccessLevel.ADMIN_ACCESS:
                    self.hosts[host][port]['accessLevel'] = accessLevel
                elif accessLevel == AccessLevel.USER_ACCESS:
                    self.hosts[host][port]['accessLevel'] = accessLevel

        # Appends A New Exploit And Output If It Does Not Exist//
        if not self.hosts[host][port].get('exploit').__contains__(exploit):
            self.hosts[host][port].get('exploit').append(exploit)
            self.hosts[host][port].get('output').append(output)

    # Function That Generates The Access Level Text To Show The User
    # @param {AccessLevel} accessLevel - The highest access level that the agent was able to obtain
    # @return A text description of the access level to inform the user
    @staticmethod
    def _getAccessLevel(accessLevel: AccessLevel) -> str:
        switch: Dict[AccessLevel, str] = {
            accessLevel.NO_ACCESS    : 'No access was obtained',
            accessLevel.USER_ACCESS  : 'User level access was obtained',
            accessLevel.ADMIN_ACCESS : 'Admin level access was obtained'
        }
        return switch[accessLevel]