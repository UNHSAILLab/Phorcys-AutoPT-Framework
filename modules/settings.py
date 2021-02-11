#This file contains the config parsing - objec
# TODO: write header information


class Singleton(type):
    """TODO: write comments.
    How to make a class a singleton

    """
    instance = None
    def __call__(cls, *args, **kw):
        # create instance if not there otherwise use same one.
        if not cls.instance:
            cls.instance = super(Singleton, cls).__call__(*args, **kw)
        return cls.instance

class Settings(metaclass=Singleton):
    """TODO: write comments.

        Need to do some validation for __init__ as well.
        probably do some Quality Asssurance later on.
        uses metaclass to make this object be a singleton 
        python doesn't have singletons
        so i had to create a method to have it act as one.
    """
    def __init__(self, nettacker_ip=None, nettacker_port=None, 
                 nettacker_key=None, metasploit_ip=None, 
                 metasploit_port=None, target=None, metasploit_password=None):
        
        self.nettacker_ip = nettacker_ip
        self.nettacker_port = nettacker_port
        self.nettacker_key = nettacker_key

        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_password = metasploit_password

        self.target = target


        # make sure all values are unpacked.
        for key in self.__dict__:
            if self.__dict__[key] is None:
                raise KeyError(f"Missing Parameter: {key}")

    def get_nettacker_port(self):
        return self.nettacker_port
    
    def get_nettacker_ip(self):
        return self.nettacker_ip

    def get_nettacker_key(self):
        return self.nettacker_key

    def get_metasploit_ip(self):
        return self.metasploit_ip

    def get_metasploit_port(self):
        return self.metasploit_port

    def get_metasploit_password(self):
        return self.metasploit_password

    def get_target(self):
        return self.target

    def get_dict(self):
        return self.__dict__