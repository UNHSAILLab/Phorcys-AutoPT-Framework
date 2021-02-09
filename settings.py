#This file contains the config parsing - object

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
print(config.sections())



# config["Metasploit"] = {'ServerIP': '127.0.0.1', 'ServerPort': '55552'}
# config["NetAttacker"] = {'IPAddress': '127.0.0.1', 'Port': '5000', 'APIKey': "XXXXXX"}

# with open('config.ini', 'w') as configfile:
#     config.write(configfile)