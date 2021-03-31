import copy
import gym
import gym.spaces as spaces
import json
import math
import numpy
import textwrap
import torch
import torch.nn.functional as F
from abc import ABC
from collections import OrderedDict
from enum import Enum
from sklearn.preprocessing import OneHotEncoder
from typing import List

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

    # <editor-fold desc="Static Variables">

    # The Service Options Available
    serviceOptions: List[List[str]] = [
        ['auxiliary/scanner/ftp/ftp_version'],
        ['auxiliary/scanner/rdp/rdp_scanner'],
        ['auxiliary/scanner/smb/smb_version'],
        ['auxiliary/scanner/ssh/ssh_version']
    ]

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

    # The Access Level Options Available
    _accessOptions: List[List[int]] = [
        [AccessLevel.NO_ACCESS.value],
        [AccessLevel.USER_ACCESS.value],
        [AccessLevel.ADMIN_ACCESS.value]
    ]

    # The Port Options Available
    _portOptions: List[List[int]] = [
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

    # </editor-fold>

    # Function that initializes the class
    # @param {AccessLevel} accessLevel     - The level of access granted for the host machine
    # @param {List[int]}   openPorts       - A list of the open ports found on the host machine by nettacker
    # @param {List[str]}   services        - A list of the services found on the open ports by metasploit
    # @param {List[str]}   vulnerabilities - A list of successful vulnerabilities performed
    # @param {str}         hostAddress     - The host machines public ipv4 address
    def __init__(
        self,
        accessLevel        : AccessLevel     = AccessLevel.NO_ACCESS,
        openPorts          : List[int]       = None,
        services           : List[str]       = None,
        vulnerabilities    : List[str]       = None,
        hostAddressOptions : List[List[str]] = None,
        hostAddress        : str             = ''
    ):
        self.hostAddressOptions = hostAddressOptions
        self._encodeAccessLevel(accessLevel)
        self._encodeHostAddress(hostAddress)
        self._encodeOpenPorts(openPorts)
        self._encodeServices(services)
        self._encodeVulnerabilities(vulnerabilities)

    # Function that decodes the access level from its state representation
    # @return {AccessLevel} The decoded access level
    def decodeAccessLevel(self) -> AccessLevel:

        # Creates The Decoder To Be Fitted With The Space Of The Access Level Options
        decoder: OneHotEncoder = OneHotEncoder().fit(self._accessOptions)

        # Gets The Decoded Access Level Number
        accessLevelNumber: int = decoder.inverse_transform(self.accessLevel.reshape(1, -1))

        # Returns The Decoded Access Level
        return AccessLevel(accessLevelNumber).name

    # Function that decodes the host address from its state representation
    # @return {str} The host machines public ipv4 address
    def decodeHostAddress(self) -> str:

        # When There Us No Host Address Saved
        if (self.hostAddress == [0, 0, 0, 0]).all():
            return ''

        # Creates The Decoder To Be Fitted With The Space Of The Host Address Options
        decoder: OneHotEncoder = OneHotEncoder().fit(self.hostAddressOptions)

        # Returns The Decoded Host Address
        return decoder.inverse_transform(self.hostAddress.reshape(1, -1))[0][0]

    # Function that decodes the open ports from its state representation
    # @return {List[int]} The decoded list of open ports
    def decodeOpenPorts(self) -> List[int]:

        # When Their Are No Open Ports Saved
        if (self.openPorts == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).all():
            return [0]

        # Generate The One Hot Encoded Array
        oneHotArray: List[List[int]] = []
        for index, item in enumerate(self.openPorts):
            if item == 1:
                port = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                port[index] = 1
                oneHotArray.append(port)

        # Creates The Decoder To Be Fitted With The Space Of The Port Options
        decoder: OneHotEncoder = OneHotEncoder().fit(self._portOptions)

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
        if (self.services == [0, 0, 0, 0]).all():
            return ['']

        # Generate The One Hot Encoded Array
        oneHotArray: List[List[int]] = []
        for index, item in enumerate(self.services):
            if item == 1:
                service = [0, 0, 0, 0]
                service[index] = 1
                oneHotArray.append(service)

        # Creates The Decoder To Be Fitted With The Space Of The Service Options
        decoder: OneHotEncoder = OneHotEncoder().fit(self.serviceOptions)

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
        if (self.vulnerabilities == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).all():
            return ['']

        # Generate The One Hot Encoded Array
        oneHotArray: List[List[int]] = []
        for index, item in enumerate(self.vulnerabilities):
            if item == 1:
                vulnerability = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                vulnerability[index] = 1
                oneHotArray.append(vulnerability)

        # Creates The Decoder To Be Fitted With The Space Of The Vulnerability Options
        decoder: OneHotEncoder = OneHotEncoder().fit(self.vulnerabilityOptions)

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
        def formatList(values: numpy.ndarray) -> str:
            formattedList: str = ''
            for value in values:
                if formattedList == '':
                    formattedList = str(value)
                else:
                    formattedList = formattedList + ' ' + str(value)
            return formattedList

        # Creates The Formatted String For Printing The State Space
        printString = f"""
        StateSpace = (
            encodedAccessLevel     = [{formatList(self.accessLevel)}]
            encodedHostAddress     = [{formatList(self.hostAddress)}]
            encodedOpenPorts       = [{formatList(self.openPorts)}]
            encodedServices        = [{formatList(self.services)}]
            encodedVulnerabilities = [{formatList(self.vulnerabilities)}]

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

        # Converts The Access Level Found To A 2D Array
        npAccessLevel: List[List[str]] = [[accessLevel.value]]

        # Creates The Encoder To Be Fitted With The Space Of The Access Level Options
        encoder: OneHotEncoder = OneHotEncoder().fit(self._accessOptions)

        # Sets The Encoded Access Level To The Access Level State
        self.accessLevel: numpy.ndarray = numpy.array(encoder.transform(npAccessLevel).toarray()[0]).astype(int)

    # Function that encodes the host address for the state using one-hot encoding
    # @param {str} hostAddress - The host machines public ipv4 address
    def _encodeHostAddress(self, hostAddress: str):

        # When No Host Address Is Found
        if hostAddress == '':
            self.hostAddress = numpy.array([0, 0, 0, 0])
            return

        # Converts The Host Address Found To A 2D Array
        npHostAddress: List[List[str]] = [[hostAddress]]

        # Creates The Encoder To Be Fitted With The Space Of The Host Address Options
        encoder: OneHotEncoder = OneHotEncoder().fit(self.hostAddressOptions)

        # Sets The Encoded Host Address To The Host Address State
        self.hostAddress: numpy.ndarray = numpy.array(encoder.transform(npHostAddress).toarray()[0]).astype(int)

    # Function that encodes the open ports for the state using one-hot encoding
    # @param {List[int]} openPorts - A list of the open ports found on the host machine by nettacker
    def _encodeOpenPorts(self, openPorts: List[int]):

        # When Their Are No Open Ports Found
        if openPorts is None:
            self.openPorts = numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            return

        # Converts The Open Ports Found To A 2D Array
        foundOpenPorts: List[List[int]] = [[openPort] for openPort in openPorts]

        # Removes The Ports That We Do Not Need
        npOpenPorts: List[List[int]] = []
        for openPort in foundOpenPorts:
            if openPort in self._portOptions:
                npOpenPorts.append(openPort)

        # Creates The Encoder To Be Fitted With The Space Of The Port Options
        encoder: OneHotEncoder = OneHotEncoder().fit(self._portOptions)

        # Encodes The Open Ports To A One Hot Encoding
        encodedOpenPorts: List[numpy.ndarray] = encoder.transform(npOpenPorts).toarray()

        # Takes The One Hot Encoded Open Ports And Merges Them
        mergedOpenPorts: numpy.ndarray = numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        for encodedOpenPort in encodedOpenPorts:
            mergedOpenPorts = numpy.logical_or(mergedOpenPorts, encodedOpenPort)

        # Sets The Encoded Open Ports To The Open Port State
        self.openPorts: numpy.ndarray = mergedOpenPorts.astype(int)

    # Function that encodes the services for the state using one-hot encoding
    # @param {List[str]} services - A list of the services found on the open ports by metasploit
    def _encodeServices(self, services: List[str]):

        # When Their Are No Services Found
        if services is None:
            self.services = numpy.array([0, 0, 0, 0])
            return

        # Converts The Services Found To A 2D Array
        npServices: List[List[str]] = [[service] for service in services]

        # Creates The Encoder To Be Fitted With The Space Of The Service Options
        encoder: OneHotEncoder = OneHotEncoder().fit(self.serviceOptions)

        # Encodes The Services To A One Hot Encoding
        encodedServices: List[numpy.ndarray] = encoder.transform(npServices).toarray()

        # Takes The One Hot Encoded Services And Merges Them
        mergedServices: numpy.ndarray = numpy.array([0, 0, 0, 0])
        for encodedService in encodedServices:
            mergedServices = numpy.logical_or(mergedServices, encodedService)

        # Sets The Encoded Services To The Services State
        self.services: numpy.ndarray = mergedServices.astype(int)

    # Function that encodes the vulnerabilities for the state using one-hot encoding
    # @param {List[str]} vulnerabilities - A list of successful vulnerabilities performed
    def _encodeVulnerabilities(self, vulnerabilities: List[str]):

        # When Their Are No Vulnerabilities Found
        if vulnerabilities is None:
            self.vulnerabilities = numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            return

        # Converts The Vulnerabilities Found To A 2D Array
        npVulnerabilities: List[List[str]] = [[vulnerability] for vulnerability in vulnerabilities]

        # Creates The Encoder To Be Fitted With The Space Of The Vulnerability Options
        encoder: OneHotEncoder = OneHotEncoder().fit(self.vulnerabilityOptions)

        # Encodes The Vulnerabilities To A One Hot Encoding
        encodedVulnerabilities: List[numpy.ndarray] = encoder.transform(npVulnerabilities).toarray()

        # Takes The One Hot Encoded Vulnerabilities And Merges Them
        mergedVulnerabilities: numpy.ndarray = numpy.array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        for encodedVulnerability in encodedVulnerabilities:
            mergedVulnerabilities = numpy.logical_or(mergedVulnerabilities, encodedVulnerability)

        # Sets The Encoded Vulnerabilities To The Vulnerabilities State
        self.vulnerabilities: numpy.ndarray = mergedVulnerabilities.astype(int)

# Python Class StateParser
# Class That Parses The Json Data And Stores It In A List Of State Spaces
# @author Jordan Zimmitti
class StateParser:

    # Function that initializes the class
    # @param {str} fileDirectory - The directory of where the file is stored
    def __init__(self, fileDirectory: str):

        # Opens The Json File And Loads The Host Data Into A List
        jsonFile : TextIO     = open(fileDirectory)
        hostList : List[dict] = json.load(jsonFile)

        # A List Of The State Spaces Parsed From The Json File
        self.stateSpaces: List[StateSpace] = []

        # Gets All The Host Addresses Found By Nettacker
        hostOptions: List[List[str]] = self._generateHostAddressOptions(hostList)

        # Generates A List Of State Spaces From The Host List
        self._generateStateSpaces(hostList, hostOptions)

    # Function That Gets All Of The Host Addresses Found By Nettacker
    # @param {List[dict]} hostList - A List Of Hosts From The Json File
    # @return {List[List[str]]} All of the host addresses found
    def _generateHostAddressOptions(self, hostList: List[dict]):

        # Appends Each Host Address Found
        hostAddressOptions = []
        for host in hostList:
            hostAddress: str = self._getHostAddress(host)
            hostAddressOptions.append([hostAddress])

        # Returns All Of The Host Addresses
        return hostAddressOptions

    # Function That Generates A List Of State Spaces From The Host List
    # @param {List[dict]}      hostList    - A List Of Hosts From The Json File
    # @param {List[List[str]]} hostOptions - All of the host addresses found
    def _generateStateSpaces(self, hostList: List[dict], hostOptions: List[List[str]]):

        # Parses Each Host In The Host List
        for host in hostList:

            # Gets The Host Data
            hostAddress : str  = self._getHostAddress(host)
            openPorts   : list = self._getOpenPorts(host)

            # Creates A State Space From The Host Data
            newStateSpace = StateSpace(
                accessLevel        = AccessLevel.NO_ACCESS,
                openPorts          = openPorts,
                hostAddressOptions = hostOptions,
                hostAddress        = hostAddress,
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
class ObservationSpace(spaces.Dict, ABC):

    # Function that initializes the class
    def __init__(self):

        # Defines The State Space And Initial State Space
        self._stateSpaces        : List[StateSpace] = StateParser('input.json').stateSpaces
        self._initialStateSpaces : List[StateSpace] = self._stateSpaces

        # Gets The Amount Of Host Address Options To Chose From
        hostAddressCount = len(self._stateSpaces[0].hostAddressOptions)

        # Defines The Scope Of The Observation Space
        self._obvSpace: OrderedDict = OrderedDict({
            'accessLevel'     : spaces.MultiBinary(3),
            'hostAddress'     : spaces.MultiBinary(hostAddressCount),
            'openPorts'       : spaces.MultiBinary(16),
            'services'        : spaces.MultiBinary(4),
            'vulnerabilities' : spaces.MultiBinary(10)
        })

        # Generates The Observation State Space And Initial Observation State Space
        self._obvStates: List[OrderedDict] = []
        self._generateObvState()

        # Initialize The Gym Space
        spaces.Dict.__init__(self, self._obvSpace)

    # Function that generates the initial observation state
    def _generateObvState(self):

        # Generates The List Of Observation States For Each State Space
        self._obvStates = []
        for obvState in self._stateSpaces:
            self._obvStates.append(
                OrderedDict({
                    'accessLevel'     : obvState.accessLevel,
                    'hostAddress'     : obvState.hostAddress,
                    'openPorts'       : obvState.openPorts,
                    'services'        : obvState.services,
                    'vulnerabilities' : obvState.vulnerabilities
                })
            )

        # Saves A Copy Of The Initial Observation State
        self._initialObvStates: List[OrderedDict] = self._obvStates

    # Function that gets the access level enum from the inputted string
    # @param {str} accessLevel - The access level as a string
    @staticmethod
    def getAccessLevel(accessLevel: str) -> AccessLevel:
        if   accessLevel == 'root': return AccessLevel.ADMIN_ACCESS
        elif accessLevel == 'NT\\AUTHORITY SYSTEM': return AccessLevel.ADMIN_ACCESS
        elif accessLevel == 'USER_ACCESS': return AccessLevel.USER_ACCESS
        else: return AccessLevel.NO_ACCESS

    # Function that returns a copy of yhe initial observation state
    # @return {OrderedDict} A copy of the initial observation state
    def getInitialObvState(self) -> OrderedDict:
        return copy.deepcopy(self._initialObvStates[0])

    # Function That Gets A Single Observation
    # {str} hostAddress - The target host address
    # @return {OrderedDict} The observation state that matches the inputted host address
    def getObservation(self, hostAddress: str) -> OrderedDict:
        for index, stateSpace in enumerate(self._stateSpaces):
            if stateSpace.decodeHostAddress() == hostAddress:
                return self._obvStates[index]

    # Function That Updates The State With The New Data
    # @param {str}         hostAddress - The target host address
    # @param {AccessLevel} accessLevel - The level of access granted for the host machine
    # @param {int}         port        - The port that was used by the exploit
    # @param {str}         exploit     - The exploit that was used
    # @return {OrderedDict} The updated observation state
    def updateState(self, hostAddress: str, accessLevel: AccessLevel, port: int, exploit: str) -> OrderedDict:

        # Gets The Current State Associated With The Host Address If It Exists//
        currentIndex: int or None = None
        currentStateSpace: StateSpace or None = None
        for index, stateSpace in enumerate(self._stateSpaces):
            if stateSpace.decodeHostAddress() == hostAddress:
                currentIndex = index
                currentStateSpace = stateSpace

        # Checks If A State Was Found
        if currentStateSpace is None or currentIndex is None:
            raise Exception('No state exists with the inputted host address')

        # When A Port Where An Exploit Was Found Was Not In The List Of Current Open Ports
        currentOpenPorts: List[int] = currentStateSpace.decodeOpenPorts()
        if not currentOpenPorts.__contains__(port):
            if currentOpenPorts[0] == 0:
                currentOpenPorts[0] = port
            else:
                currentOpenPorts.append(port)

        # When An Exploit Found Is A Service And Is Not In The List Of Current Services
        currentServices: List[str] or None = currentStateSpace.decodeServices()
        if StateSpace.serviceOptions.__contains__([exploit]):
            if not currentServices.__contains__(exploit):
                if currentServices[0] == '':
                    currentServices[0] = exploit
                else:
                    currentServices.append(exploit)
        elif currentServices[0] == '':
            currentServices = None

        # When An Exploit Found Is A Vulnerability And Is Not In The List Of Current Vulnerabilities
        currentVulnerabilities: List[str] or None = currentStateSpace.decodeVulnerabilities()
        if StateSpace.vulnerabilityOptions.__contains__([exploit]):
            if not currentVulnerabilities.__contains__(exploit):
                if currentVulnerabilities[0] == '':
                    currentVulnerabilities[0] = exploit
                else:
                    currentVulnerabilities.append(exploit)
        elif currentVulnerabilities[0] == '':
            currentVulnerabilities = None

        # Updates The Current State With The New Data//
        self._stateSpaces[currentIndex] = StateSpace(
            accessLevel        = accessLevel,
            openPorts          = currentOpenPorts,
            services           = currentServices,
            vulnerabilities    = currentVulnerabilities,
            hostAddressOptions = self._stateSpaces[currentIndex].hostAddressOptions,
            hostAddress        = hostAddress
        )

        # Updates The Current Observation State With The New Data//
        self._obvStates[currentIndex] = OrderedDict({
            'accessLevel'     : self._stateSpaces[currentIndex].accessLevel,
            'hostAddress'     : self._stateSpaces[currentIndex].hostAddress,
            'openPorts'       : self._stateSpaces[currentIndex].openPorts,
            'services'        : self._stateSpaces[currentIndex].services,
            'vulnerabilities' : self._stateSpaces[currentIndex].vulnerabilities
        })

        # Returns The Updated Observation State
        return self._obvStates[currentIndex]
