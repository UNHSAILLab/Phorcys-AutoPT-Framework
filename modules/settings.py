#This file contains the config parsing - object
# TODO: write header information


class Singleton(type):
    """Metaclass that can be used to allow a class to be a Singleton."""
    instance = None
    def __call__(cls, *args, **kw):
        # create instance if not there otherwise use same one.
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance

class Settings(metaclass=Singleton):
    """
        This class creates a Singleton for all of the necessary settings for the platform. All portions of the system
        can access this information as needed.

        __init__:
        :param str nettacker_ip: IP address for the nettacker API Server
        :param int nettacker_port: Port for nettacker API
        :param str nettacker_ket: API Key needed for nettacker API
        :param str metasploit_ip: IP address for Metasploit RPC API Server
        :param int metasploit_port: Port assigned to Metasploit RPC API
        :param str target: This is the target IP address, Domain, or network
        :param str metasploit_password: Metasploit RPC API password
    """

    def __init__(self, nettacker_ip: str, nettacker_port: int, nettacker_key: str, metasploit_ip: str, 
                 metasploit_port: int, target: str, metasploit_password: str):
        
        self.nettacker_ip = nettacker_ip
        self.nettacker_port = nettacker_port
        self.nettacker_key = nettacker_key

        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_password = metasploit_password

        self.target = target

        # self.verbosity = verbosity
        # make sure all values are unpacked.
        for key in self.__dict__:
            if self.__dict__[key] is None:
                raise KeyError(f"Missing Parameter: {key}")

    def get_nettacker_port(self) -> int:
        """ This returns the port information of the nettacker API
            :param self - This tells the program to access the port that has been initialized in the instance
            :return self.nettacker_port - Returns the port
        """
        return self.nettacker_port
        
    def get_nettacker_ip(self) -> str:
        """ This returns the IP address of the nettacker API
            :param self - This tells the program to access the nettacker_ip initialized in the instance parameters
            :return nettacker_IP - Returns the IP address hosting nettacker
        """
        return self.nettacker_ip

    def get_nettacker_key(self) -> str:
        """ This returns the API Key needed for Nettacker API
            :param self - This tells the program to access the nettacker_key initialized in the instance parameters
            :return nettacker_key - Returns the nettacker API Key initialized in the instance
        """
        return self.nettacker_key

    def get_metasploit_ip(self) -> int:
        """ This returns the Server IP for the Metasploit RPC API
            :param self - This tells the program to access the metasploit_ip initialized in the instance parameters
            :return metasploit_ip - Returns the IP that is hosting the Metsploit RPC API server
        """
        return self.metasploit_ip

    def get_metasploit_port(self) -> str:
        """ This returns the port for the Metasploit RPC API
            :param self - This tells the program to access the metasploit_port initialized in the instance parameters
            :return metasploit_port - Returns the Port to the Metsploit RPC API server
        """
        return self.metasploit_port

    def get_metasploit_password(self) -> str:
        """ This returns the Metasploit RPC API Port
            :param self - This tells the program to access the metasploit_password initialized in the instance 
                parameters
            :return self.metasploit_port - Returns the password to the Metsploit RPC API server
        """
        return self.metasploit_password

    def get_target(self) -> str:
        """ This Returns the Target IP, Domain or Range
            :param self - This tells the program to access the target initialized in the instance parameters
            :return self.target - Returns the Target IP Address, Domain, or range
        """

        return self.target


    def get_dict(self) -> dict:
        """ This creates a dictionary for all the necessary settings
            :param self - This tells the program to access and create a dictionary of all initialized settings
            :return self.__dict__ - Returns the dictionary of all the necessary settings
        """
        return self.__dict__