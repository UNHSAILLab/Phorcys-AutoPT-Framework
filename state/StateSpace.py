import copy
from abc import ABC

import gym
import gym.spaces as spaces
import json
import math
import numpy
import textwrap
import torch
import torch.nn.functional as F
from collections import OrderedDict
from enum import Enum
from typing import List
from sklearn.preprocessing import MinMaxScaler, StandardScaler, Normalizer, OneHotEncoder

# Enum Class AccessLevel
# Class For Describing Access Levels
# @author Jordan Zimmitti
class AccessLevel(Enum):
    NO_ACCESS    = 0
    USER_ACCESS  = 1
    ADMIN_ACCESS = 2

# Python Class StateSpace
# Class For Encoding And Decoding The State Space
# @author Jordan Zimmitti
class StateSpace:

    # <editor-fold desc="Class Variables">

    # An Encoded List Of The Level Of Access Obtained For The Machine
    accessLevel: List[numpy.ndarray] = []

    # An Encoded List Of The Host Machine's Public IPv4 Address
    hostAddress: List[numpy.ndarray] = []

    # An Encoded List Of The Open Ports Found On The Host Machine By Nettacker During Recognizance
    openPorts: List[numpy.ndarray] = []

    # An Encoded List Of The Services Found On The Open Ports By Metasploit
    services: List[numpy.ndarray] = []

    # An Encoded List Of Successful Vulnerabilities Performed
    vulnerabilities: List[numpy.ndarray] = []

    # </editor-fold>

    # Function that initializes the class
    # @param {AccessLevel} accessLevel     - The level of access granted for the host machine
    # @param {List[int]}   openPorts       - A list of the open ports found on the host machine by nettacker
    # @param {List[str]}   services        - A list of the services found on the open ports by metasploit
    # @param {List[str]}   vulnerabilities - A list of successful vulnerabilities performed
    # @param {str}         hostAddress     - The host machines public ipv4 address
    def __init__(
        self,
        accessLevel     : AccessLevel = AccessLevel.NO_ACCESS,
        openPorts       : List[int]   = None,
        services        : List[str]   = None,
        vulnerabilities : List[str]   = None,
        hostAddress     : str         = ''
    ):
        self._encodeAccessLevel(accessLevel)
        self._encodeHostAddress(hostAddress)
        self._encodeOpenPorts(openPorts)
        self._encodeServices(services)
        self._encodeVulnerabilities(vulnerabilities)

    # Function that decodes the access level from its state representation
    # @return {AccessLevel} The decoded access level
    def decodeAccessLevel(self) -> AccessLevel:

        # The Access Level Options Available
        accessOptions: List[List[int]] = [
            [AccessLevel.NO_ACCESS.value],
            [AccessLevel.USER_ACCESS.value],
            [AccessLevel.ADMIN_ACCESS.value]
        ]

        # Creates The Decoder To Be Fitted With The Space Of The Access Level Options
        decoder: OneHotEncoder = OneHotEncoder().fit(accessOptions)

        # Gets The Decoded Access Level Number
        accessLevelNumber: int = decoder.inverse_transform(self.accessLevel)[0][0]

        # Returns The Decoded Access Level
        return AccessLevel(accessLevelNumber).name

    # Function that decodes the host address from its state representation
    # @return {str} The host machines public ipv4 address
    def decodeHostAddress(self) -> str:

        # When There Us No Host Address Saved
        if (self.hostAddress[0] == [0, 0, 0, 0]).all():
            return ''

        # The Host Address Options Available
        hostAddressOptions: List[List[str]] = [
            ['192.168.1.100'],
            ['192.168.1.183'],
            ['192.168.1.200'],
            ['192.168.1.201']
        ]

        # Creates The Decoder To Be Fitted With The Space Of The Host Address Options
        decoder: OneHotEncoder = OneHotEncoder().fit(hostAddressOptions)

        # Returns The Decoded Host Address
        return decoder.inverse_transform(self.hostAddress)[0][0]

    # Function that decodes the open ports from its state representation
    # @return {List[int]} The decoded list of open ports
    def decodeOpenPorts(self) -> List[int]:

        # When Their Are No Open Ports Saved
        if (self.openPorts[0] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).all():
            return [0]

        # The Port Options Available
        portOptions: List[List[int]] = [
            [21],
            [22],
            [53],
            [80],
            [88],
            [135],
            [139],
            [389],
            [443],
            [445],
            [464],
            [593],
            [636],
            [3268],
            [3269],
            [3389]
        ]

        # Generate The One Hot Encoded Array
        oneHotArray: List[List[int]] = []
        for index, item in enumerate(self.openPorts[0]):
            if item == 1:
                port = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                port[index] = 1
                oneHotArray.append(port)

        # Creates The Decoder To Be Fitted With The Space Of The Port Options
        decoder: OneHotEncoder = OneHotEncoder().fit(portOptions)

        # Gets The Decoded Services As A 2D Array
        npOpenPorts: List[List[int]] = decoder.inverse_transform(oneHotArray)

        # Converts The Open Ports To A Normal Array
        openPorts: List[int] = []
        for openPortArray in npOpenPorts:
            for openPort in openPortArray:
                openPorts.append(openPort)

        # Returns The Decoded List Of Open Ports
        return openPorts

    # Function that decodes the services from its state representation
    # @return {List[str]} The decoded list of services
    def decodeServices(self) -> List[str]:

        # When There Are No Services Saved
        if (self.services[0] == [0, 0, 0, 0]).all():
            return ['']

        # The Service Options Available
        serviceOptions: List[List[str]] = [
            ['auxiliary/scanner/ftp/ftp_version'],
            ['auxiliary/scanner/rdp/rdp_scanner'],
            ['auxiliary/scanner/smb/smb_version'],
            ['auxiliary/scanner/ssh/ssh_version']
        ]

        # Generate The One Hot Encoded Array
        oneHotArray: List[List[int]] = []
        for index, item in enumerate(self.services[0]):
            if item == 1:
                service = [0, 0, 0, 0]
                service[index] = 1
                oneHotArray.append(service)

        # Creates The Decoder To Be Fitted With The Space Of The Service Options
        decoder: OneHotEncoder = OneHotEncoder().fit(serviceOptions)

        # Gets The Decoded Services As A 2D Array
        npServices: List[List[str]] = decoder.inverse_transform(oneHotArray)

        # Converts The Services To A Normal Array
        services: List[str] = []
        for serviceArray in npServices:
            for service in serviceArray:
                services.append(service)

        # Returns The Decoded List Of Services
        return services

    # Function that decodes the vulnerabilities from its state representation
    # @return {List[str]} The decoded list of vulnerabilities
    def decodeVulnerabilities(self) -> List[str]:

        # When There Are No Vulnerabilities Saved
        if (self.vulnerabilities[0] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).all():
            return ['']

        # The Vulnerability Options Available
        vulnerabilityOptions: List[List[str]] = [
            ['auxiliary/scanner/ftp/anonymous'],
            ['auxiliary/scanner/ftp/ftp_login'],
            ['auxiliary/scanner/rdp/cve_2019_0708_bluekeep'],
            ['auxiliary/scanner/smb/smb_login'],
            ['auxiliary/scanner/smb/smb_ms17_010'],
            ['auxiliary/scanner/ssh/ssh_login'],
            ['exploit/unix/ftp/proftpd_133c_backdoor'],
            ['exploit/windows/rdp/cve_2019_0708_bluekeep_rce'],
            ['exploit/windows/smb/ms17_010_eternalblue'],
            ['exploit/windows/smb/psexec']
        ]

        # Generate The One Hot Encoded Array
        oneHotArray: List[List[int]] = []
        for index, item in enumerate(self.vulnerabilities[0]):
            if item == 1:
                vulnerability = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                vulnerability[index] = 1
                oneHotArray.append(vulnerability)

        # Creates The Decoder To Be Fitted With The Space Of The Vulnerability Options
        decoder: OneHotEncoder = OneHotEncoder().fit(vulnerabilityOptions)

        # Gets The Decoded Vulnerabilities As A 2D Array
        npVulnerabilities: List[List[str]] = decoder.inverse_transform(oneHotArray)

        # Converts The Vulnerabilities To A Normal Array
        vulnerabilities: List[str] = []
        for vulnerabilitiesArray in npVulnerabilities:
            for vulnerability in vulnerabilitiesArray:
                vulnerabilities.append(vulnerability)

        # Returns The Decoded List Of Vulnerabilities
        return vulnerabilities

    # Function That Prints The State Space Object In A Nicely Formatted Way
    #
    def print(self):

        # Function That Formats A List To Be Printed Horizontally
        # @param {List} values - The list to format
        # @return {str} The formatted list as a string
        def formatList(values: List) -> str:
            formattedList: str = ''
            for value in values:
                if formattedList == '':
                    formattedList = '[' + str(value) + ']'
                else:
                    formattedList = formattedList + ' ' + '[' + str(value) + ']'
            return formattedList

        # Creates The Formatted String For Printing The State Space
        printString = f"""
        StateSpace = (
            encodedAccessLevel     = {formatList(self.accessLevel)}
            encodedHostAddress     = {formatList(self.hostAddress)}
            encodedOpenPorts       = {formatList(self.openPorts)}
            encodedServices        = {formatList(self.services)}
            encodedVulnerabilities = {formatList(self.vulnerabilities)}

            decodedAccessLevel     = {self.decodeAccessLevel()}
            decodedHostAddress     = {self.decodeHostAddress()}
            decodedOpenPorts       = {self.decodeOpenPorts()}
            decodedServices        = {self.decodeServices()}
            decodedVulnerabilities = {self.decodeVulnerabilities()}
        )
        """
        print(textwrap.dedent(printString), end='')

    # Function that encodes the access level for the state using one-hot encoding
    # @param {AccessLevel} accessLevel - The level of access granted for the host machine
    def _encodeAccessLevel(self, accessLevel: AccessLevel):

        # The Access Level Options Available
        accessOptions: List[List[int]] = [
            [AccessLevel.NO_ACCESS.value],
            [AccessLevel.USER_ACCESS.value],
            [AccessLevel.ADMIN_ACCESS.value]
        ]

        # Converts The Access Level Found To A 2D Array
        npAccessLevel: List[List[str]] = [[accessLevel.value]]

        # Creates The Encoder To Be Fitted With The Space Of The Access Level Options
        encoder: OneHotEncoder = OneHotEncoder().fit(accessOptions)

        # Sets The Encoded Access Level To The Access Level State
        self.accessLevel = [numpy.array(encoder.transform(npAccessLevel).toarray()[0])]

    # Function that encodes the host address for the state using one-hot encoding
    # @param {str} hostAddress - The host machines public ipv4 address
    def _encodeHostAddress(self, hostAddress: str):

        # When No Host Address Is Found
        if hostAddress == '':
            self.hostAddress = [numpy.array([0, 0, 0, 0])]
            return

        # The Host Address Options Available
        hostAddressOptions: List[List[str]] = [
            ['192.168.1.100'],
            ['192.168.1.183'],
            ['192.168.1.200'],
            ['192.168.1.201']
        ]

        # Converts The Host Address Found To A 2D Array
        npHostAddress: List[List[str]] = [[hostAddress]]

        # Creates The Encoder To Be Fitted With The Space Of The Host Address Options
        encoder: OneHotEncoder = OneHotEncoder().fit(hostAddressOptions)

        # Sets The Encoded Host Address To The Host Address State
        self.hostAddress = [numpy.array(encoder.transform(npHostAddress).toarray()[0])]

    # Function that encodes the open ports for the state using one-hot encoding
    # @param {List[int]} openPorts - A list of the open ports found on the host machine by nettacker
    def _encodeOpenPorts(self, openPorts: List[int]):

        # When Their Are No Open Ports Found
        if openPorts is None:
            self.openPorts = [numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]
            return

        # The Port Options Available
        portOptions: List[List[int]] = [
            [21],
            [22],
            [53],
            [80],
            [88],
            [135],
            [139],
            [389],
            [443],
            [445],
            [464],
            [593],
            [636],
            [3268],
            [3269],
            [3389]
        ]

        # Converts The Open Ports Found To A 2D Array
        foundOpenPorts: List[List[int]] = [[openPort] for openPort in openPorts]

        # Removes The Ports That We Do Not Need
        npOpenPorts: List[List[int]] = []
        for openPort in foundOpenPorts:
            if openPort in portOptions:
                npOpenPorts.append(openPort)

        # Creates The Encoder To Be Fitted With The Space Of The Port Options
        encoder: OneHotEncoder = OneHotEncoder().fit(portOptions)

        # Encodes The Open Ports To A One Hot Encoding
        encodedOpenPorts: List[numpy.ndarray] = encoder.transform(npOpenPorts).toarray()

        # Takes The One Hot Encoded Open Ports And Merges Them
        mergedOpenPorts: numpy.ndarray = numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        for encodedOpenPort in encodedOpenPorts:
            mergedOpenPorts = numpy.logical_or(mergedOpenPorts, encodedOpenPort)

        # Sets The Encoded Open Ports To The Open Port State
        self.openPorts = [mergedOpenPorts.astype(float)]

    # Function that encodes the services for the state using one-hot encoding
    # @param {List[str]} services - A list of the services found on the open ports by metasploit
    def _encodeServices(self, services: List[str]):

        # When Their Are No Services Found
        if services is None:
            self.services = [numpy.array([0, 0, 0, 0])]
            return

        # The Service Options Available
        serviceOptions: List[List[str]] = [
            ['auxiliary/scanner/ftp/ftp_version'],
            ['auxiliary/scanner/rdp/rdp_scanner'],
            ['auxiliary/scanner/smb/smb_version'],
            ['auxiliary/scanner/ssh/ssh_version']
        ]

        # Converts The Services Found To A 2D Array
        npServices: List[List[str]] = [[service] for service in services]

        # Creates The Encoder To Be Fitted With The Space Of The Service Options
        encoder: OneHotEncoder = OneHotEncoder().fit(serviceOptions)

        # Encodes The Services To A One Hot Encoding
        encodedServices: List[numpy.ndarray] = encoder.transform(npServices).toarray()

        # Takes The One Hot Encoded Services And Merges Them
        mergedServices: numpy.ndarray = numpy.array([0, 0, 0, 0])
        for encodedService in encodedServices:
            mergedServices = numpy.logical_or(mergedServices, encodedService)

        # Sets The Encoded Services To The Services State
        self.services = [mergedServices.astype(float)]

    # Function that encodes the vulnerabilities for the state using one-hot encoding
    # @param {List[str]} vulnerabilities - A list of successful vulnerabilities performed
    def _encodeVulnerabilities(self, vulnerabilities: List[str]):

        # When Their Are No Vulnerabilities Found
        if vulnerabilities is None:
            self.vulnerabilities = [numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]
            return

        # The Vulnerability Options Available
        vulnerabilityOptions: List[List[str]] = [
            ['auxiliary/scanner/ftp/anonymous'],
            ['auxiliary/scanner/ftp/ftp_login'],
            ['auxiliary/scanner/rdp/cve_2019_0708_bluekeep'],
            ['auxiliary/scanner/smb/smb_login'],
            ['auxiliary/scanner/smb/smb_ms17_010'],
            ['auxiliary/scanner/ssh/ssh_login'],
            ['exploit/unix/ftp/proftpd_133c_backdoor'],
            ['exploit/windows/rdp/cve_2019_0708_bluekeep_rce'],
            ['exploit/windows/smb/ms17_010_eternalblue'],
            ['exploit/windows/smb/psexec']
        ]

        # Converts The Vulnerabilities Found To A 2D Array
        npVulnerabilities: List[List[str]] = [[vulnerability] for vulnerability in vulnerabilities]

        # Creates The Encoder To Be Fitted With The Space Of The Vulnerability Options
        encoder: OneHotEncoder = OneHotEncoder().fit(vulnerabilityOptions)

        # Encodes The Vulnerabilities To A One Hot Encoding
        encodedVulnerabilities: List[numpy.ndarray] = encoder.transform(npVulnerabilities).toarray()

        # Takes The One Hot Encoded Vulnerabilities And Merges Them
        mergedVulnerabilities: numpy.ndarray = numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        for encodedVulnerability in encodedVulnerabilities:
            mergedVulnerabilities = numpy.logical_or(mergedVulnerabilities, encodedVulnerability)

        # Sets The Encoded Vulnerabilities To The Vulnerabilities State
        self.vulnerabilities = [mergedVulnerabilities.astype(float)]

# Python Class StateParser
# Class That Parses The Json Data And Stores It In A List Of State Spaces
# @author Jordan Zimmitti
class StateParser:

    # A List Of The State Spaces Parsed From The Json File
    stateSpaces: List[StateSpace] = []

    # Function that initializes the class
    # @param {str} fileDirectory - The directory of where the file is stored
    def __init__(self, fileDirectory: str):

        # Opens The Json File And Loads The Host Data Into A List
        jsonFile : TextIO     = open(fileDirectory)
        hostList : List[dict] = json.load(jsonFile)

        # Generates A List Of State Spaces From The Host List
        self._generateStateSpaces(hostList)

    # Function That Generates A List Of State Spaces From The Host List
    # @param {List[dict]} hostList - A List Of Hosts From The Json File
    def _generateStateSpaces(self, hostList: List[dict]):

        # Parses Each Host In The Host List
        for host in hostList:

            # Gets The Host Data
            hostAddress : str  = self._getHostAddress(host)
            openPorts   : list = self._getOpenPorts(host)

            # Creates A State Space From The Host Data
            newStateSpace = StateSpace(
                accessLevel     = AccessLevel.NO_ACCESS,
                openPorts       = openPorts,
                hostAddress     = hostAddress,
                services        =['auxiliary/scanner/ftp/ftp_version', 'auxiliary/scanner/ssh/ssh_version'],
                vulnerabilities =['auxiliary/scanner/ftp/anonymous', 'exploit/windows/smb/ms17_010_eternalblue']
            )

            # Adds The State Space To The State Spaces List
            self.stateSpaces.append(newStateSpace)

    # Function That Parses The Host Address From The Host
    # @return {str} The host address
    @staticmethod
    def _getHostAddress(host: dict) -> str:
        return host.get('host')

    # Function That Parses The Open Ports From The Host
    # @return {List[int]} The list of open ports
    @staticmethod
    def _getOpenPorts(host: dict) -> List[int]:

        # Creates The Opened Port List And Gets The Unparsed Open Port List
        openPortList: List[int] = []
        unparsedOpenPortList: List[str] = host.get('info').get('descriptions')

        # Parses The Open Ports
        for port in unparsedOpenPortList:
            openPort = port.split('/')[0]
            openPortList.append(int(openPort))

        # Returns The List Of Open Ports
        return openPortList

# Python Class ObservationSpace
# Class That Creates And Handles The Observation Space
# @author Jordan Zimmitti
class ObservationSpace(gym.Space, ABC):

    # Parses The JSON Data To Create The State Space
    stateSpaces: List[StateSpace] = StateParser('input.json').stateSpaces

    # The Generated Initial Observation State
    _initialObvState: OrderedDict = OrderedDict()

    # Function that initializes the class
    def __init__(self):

        # Defines The Observation Space As A Ordered Dict
        obvSpace: OrderedDict = OrderedDict()

        # Iterate Through Each State In The State Space
        for stateSpace in self.stateSpaces:

            # Describe The Observation State For Each Host
            hostAddress = stateSpace.decodeHostAddress()
            obvSpace[hostAddress] = spaces.Dict({
                'accessLevel'     : spaces.MultiBinary(3),
                'hostAddress'     : spaces.MultiBinary(4),
                'openPorts'       : spaces.MultiBinary(16),
                'services'        : spaces.MultiBinary(4),
                'vulnerabilities' : spaces.MultiBinary(10)
            })

        # Initialize The Gym Space
        gym.Space.__init__(self, None, None)

        # Generates The Initial Observation State
        self._initialObvState = self._generateInitialObvState()

    # Function that generates the initial observation state
    # @return {OrderedDict} The initial observation state
    def _generateInitialObvState(self) -> OrderedDict:

        # Defines An Ordered Dict For Holding Each State
        _initialObvState: OrderedDict = OrderedDict()

        # Adds The Parsed State
        for stateSpace in self.stateSpaces:
            hostAddress = stateSpace.decodeHostAddress()
            _initialObvState[hostAddress] = OrderedDict({
                'accessLevel'     : stateSpace.accessLevel,
                'hostAddress'     : stateSpace.hostAddress,
                'openPorts'       : stateSpace.openPorts,
                'services'        : stateSpace.services,
                'vulnerabilities' : stateSpace.vulnerabilities
            })

        return _initialObvState

    # Function that returns a copy of yhe initial observation state
    # @return {OrderedDict} A copy of the initial observation state
    def getInitialObvState(self) -> OrderedDict:
        return copy.deepcopy(self._initialObvState)


stateParser = StateParser('input.json')
states = stateParser.stateSpaces
for state in states:
    state.print()

obvSpace = ObservationSpace()
obvState = obvSpace.getInitialObvState()
print()
print(obvState)
