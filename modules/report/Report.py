import pprint
from typing import Dict
from typing import List
from modules.attack_env.StateSpace import AccessLevel
from modules.attack_env.StateSpace import StateSpace

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
                'accessLevel' : accessLevel,
                'exploit'     : [exploit],
                'output'      : [output]
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

    # Function That Gets The States From The Observation And Adds The Relevant Data To The Report
    # @param {List[StateSpace]} states - A list of all of the states
    def addStateDataToReport(self, states: List[StateSpace]):

        # Adds Open Port Data From Each State To The Report
        for state in states:

            # Gets The Current Host Address
            host = state.decodeHostAddress()

            # When The Host Does Not Exist
            if host not in self.hosts:

                # Adds The Host And All Of Its Open Ports
                self.hosts[host] = {}
                for port in state.decodeOpenPorts():
                    self.hosts[host][port] = {
                        'accessLevel' : self._getAccessLevel(AccessLevel.NO_ACCESS),
                        'exploit'     : None,
                        'output'      : None
                    }
                continue

            # Adds All Of The Open Ports That Do Not Already Exist
            for port in state.decodeOpenPorts():
                if port not in self.hosts[host]:
                    self.hosts[host][port] = {
                        'accessLevel' : self._getAccessLevel(AccessLevel.NO_ACCESS),
                        'exploit'     : None,
                        'output'      : None
                    }

    # Function That Generates The Report
    # Report Is Generated using html
    def generateReport(self, image):

        # Opens The Report File
        report = open("report.html", "w")

        # Shows The Header And Phorcys Image
        report.write(f"""<!DOCTYPE html>
    <html lang="en">
    
        <!-- Head Metadata -->
        <head>
            <meta charset="UTF-8">
            <title>Phorcys Report</title>
        </head>
            
        <!-- Report Body -->
        <body style="margin: 0; padding: 0 0 1rem 0">

            <!--  Logo And Intro Info  -->
            <div>   
                <img src="{image}" alt="" style="max-height: 20rem; display: block; margin: 0 auto">
            </div>
    """)

        # Iterates Through All Hosts In The Report
        for host in self.hosts:

            # Shows The Host With Its IP Text And The Open Ports Found Title
            report.write(f"""     
            <!-- Port Divider Line -->
            <div style="border: dashed black; margin: 2rem 0 1rem 0"></div>
                
            <!--  Host Level  -->
            <span 
                style="font-family: Verdana, sans-serif; font-size: 1.3em; padding-left: 1rem">
                <b>Host - {host}</b>
            </span>
                
            <!-- Port Divider Line -->
            <div style="border: dashed black; margin: 1rem 0 1rem 0"></div>
                
            <!-- Open Port Div -->
            <div style="display: flex; flex-direction: column;">
                
                <!-- Open Ports Found Title -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1.2em; padding-left: 1rem">
                    <b>Open Ports Found:</b>
                </span> 
            </div>     
            """)

            # Iterates Through All Ports In The Host//
            for port in self.hosts[host]:

                # Gets All Of The Port Data If Any
                accessLevel : AccessLevel = self.hosts[host][port]['accessLevel']
                exploits    : List[str]   = self.hosts[host][port]['exploit']
                outputs     : List[str]   = self.hosts[host][port]['output']

                # When No Exploits Were Found
                if exploits is None:

                    # Shows The Port And The Start Of The Border
                    report.write(f"""   
            <!-- Port Div -->
            <div style="display: flex; flex-direction: column;">
                
                <!-- Port -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1.2em; padding: 1rem 0 0 1rem;">
                    <b>Port {port}:</b>
                </span> 
                    
            </div>
                
            <!-- Vulnerability Div -->
            <div style="display: flex; flex-direction: column; background-color : #EEEEEE; margin: 1rem 5rem 0 5rem; border: black; border-style: solid; border-radius: .6rem">

                <!-- Access Level -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1em; padding: 1rem 1rem 0rem 1rem;">
                    <b>Access Level:</b> {accessLevel}
                </span>
                
                <!-- Vulnerability -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1em; padding: 1rem 1rem 1rem 1rem;">
                    <b>Vulnerabilities:</b> None
                </span>
                
            </div>
                    """)

                    # Shows The Port, Access Level, And That No Exploits Were Found
                    continue

                # Shows The Port And The Start Of The Border
                report.write(f""" 
            <!-- Port Div -->
            <div style="display: flex; flex-direction: column;">      
                
                <!-- Port -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1.2em; padding: 1rem 0 0 1rem;">
                    <b>Port {port}:</b>
                </span> 
                    
            </div>
                
            <!-- Vulnerability Div -->
            <div style="display: flex; flex-direction: column; background-color : #EEEEEE; margin: 1rem 5rem 0 5rem; border: black; border-style: solid; border-radius: .6rem">
                        
                <!-- Access Level -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1em; padding: 1rem 1rem 1rem 1rem;">
                    <b>Access Level:</b> {self._getAccessLevel(accessLevel)}
                </span>
                """)

                # When Exploits Were Found
                for index in range(0, len(exploits)):
                    exploit = exploits[index]
                    output  = outputs[index]

                    # Shows The Access Level, Exploit, And Output About The Exploit
                    report.write(f"""    
                <!-- Vulnerability -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1em; padding: 1rem 1rem 0 1rem;">
                    <b>Vulnerability:</b> {exploit}
                </span> 
                        
                <!-- Description Title -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1em; padding: 1rem 1rem 0 1rem;">
                    <b>Vulnerability Description:</b>
                </span>
                        
                <!-- Description -->
                <span 
                    style="font-family: Verdana, sans-serif; font-size: 1em; padding: 1rem 1rem 1rem 1rem;">
                    {output}
                </span>
                    """)

                # Shows The End Of The Box
                report.write("""
            </div>
                """)

        # Shows The End Of The Report
        report.write("""    
        </body>
    </html>
        """)

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