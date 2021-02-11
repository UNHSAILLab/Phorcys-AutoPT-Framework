#This file contains the config parsing - object
# TODO: write header information


class Singleton(type):
    """TODO: write comments.
    The purpose of a Singleton is to provide access to a single object that is needed across an entire software platform. This ensures that if the object is changed,
    it stays uniform for all areas of a project that need it.

    Below initializes an instance of the object.
    """
    instance = None
    def __call__(cls, *args, **kw):
        # create instance if not there otherwise use same one.
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance

class Settings(metaclass=Singleton):
    """TODO: write comments.
        This class creates a Singleton for all of the necessary settings for the platform. All portions of the system can access this information as needed.

        __init__:
        :param str nettacker_ip: IP address for the nettacker API Server
        :param int nettacker_port: Port for nettacker API
        :param str nettacker_ket: API Key needed for nettacker API
        :param str metasploit_ip: IP address for Metasploit RPC API Server
        :param int metasploit_port: Port assigned to Metasploit RPC API
        :param str target: This is the target IP address, Domain, or network
        :param str metasploit_password: Metasploit RPC API password
    
        Need to do some validation for __init__ as well.
        probably do some Quality Asssurance later on.
        uses metaclass to make this object be a singleton 
        python doesn't have singletons
        so i had to create a method to have it act as one.
    """
    def __init__(self, nettacker_ip: str, nettacker_port: int, 
                 nettacker_key: str, metasploit_ip: str, 
                 metasploit_port: int, target: str, metasploit_password: str):
        
        self.nettacker_ip = nettacker_ip
        self.nettacker_port = nettacker_port
        self.nettacker_key = nettacker_key

        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_password = metasploit_password

        self.target = target

        # make sure all values are unpacked.
        """ This ensures that all values in the dictionary are initialized """
        for key in self.__dict__:
            if self.__dict__[key] is None:
                raise KeyError(f"Missing Parameter: {key}")


    """ The following functions return the settings information:

        get_nettacker_port():
        :param self - This tells the program to access the nettacker_port initialized in the instance parameters
        :return nettacker_port  - Returns the port

        get_nettacker_ip():
        :param self - This tells the program to access the nettacker_ip initialized in the instance parameters
        :return nettacker_IP - Returns the IP address hosting nettacker

        get_nettacker_key():
        :param self - This tells the program to access the nettacker_key initialized in the instance parameters
        :return nettacker_key - Returns the nettacker API Key initialized in the instance

        get_metasploit_ip():
        :param self - This tells the program to access the metasploit_ip initialized in the instance parameters
        :return metasploit_ip: Returns the IP that is hosting the Metsploit RPC API server

        get_metasploit_port():
        :param self - This tells the program to access the metasploit_port initialized in the instance parameters
        :return metasploit_port: Returns the Port to the Metsploit RPC API server

        get_metasploit_password():
        :param self - This tells the program to access the metasploit_password initialized in the instance parameters
        :return self.metasploit_port: Returns the password to the Metsploit RPC API server

        get_target():
        :param self - This tells the program to access the target initialized in the instance parameters
        :return self.target: Returns the Target IP Address, Domain, or range

        get_dict():
        :param self - This tells the program to access and create the dictionary of all the settings parameters that have been initialized
        :return self.__dict__  - Returns the dictionary of all the necessary settings
    """
    def get_nettacker_port(self) -> int:
        return self.nettacker_port
    
    def get_nettacker_ip(self) -> str:
        return self.nettacker_ip

    def get_nettacker_key(self) -> str:
        return self.nettacker_key

    def get_metasploit_ip(self) -> int:
        return self.metasploit_ip

    def get_metasploit_port(self) -> str:
        return self.metasploit_port

    def get_metasploit_password(self) -> str:
        return self.metasploit_password

    def get_target(self) -> str:
        return self.target

    def get_dict(self) -> dict:
        return self.__dict__