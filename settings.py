#This file contains the config parsing - object

import configparser

class Config:
    config = configparser.ConfigParser()
    config.read('config.ini')
    print(config.sections())

# ****** GET METASPLOIT INFO *****  
    def getMetasploitServer(self):
        metaServerIP = config.get('Metasploit', 'ServerIP')
        return metaServerIP
            
    def get_Metasploit_Port(self):
        metaPort = config.get('Metasploit', 'ServerPort')
        return metaPort
    
    def get_Metasploit_Password(self):
        metaPassword = config.get("Metasploit", 'Password')
        return metaPassword

# **** GET NETTACKER INFO *****
    def get_Nettacker_ip(self):
        nettackerIP = config.get('Nettacker', 'ipaddress')
        return nettackerIP
    
    def get_Nettacker_port(self):
        nettackerPort = config.get('Nettacker', 'Port')
        return nettackerPort
    
    def get_nettacker_key(self):
        nettackerKey = config.get('Nettacker', 'APIKey')
        return nettackerKey
        
if __name__ == '__settings__':
   x = Config()
   x.getMetasploitServer()
   print(x)

# config["Metasploit"] = {'ServerIP': '127.0.0.1', 'ServerPort': '55552', 'Password':'XXXXXXX'}
# config["Nettacker"] = {'IPAddress': '127.0.0.1', 'Port': '5000', 'APIKey': "XXXXXX"}

# with open('config.ini', 'w') as configfile:
#     config.write(configfile)