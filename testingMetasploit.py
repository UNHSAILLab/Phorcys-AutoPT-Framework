import os, sys
import argparse
import ipaddress
import textwrap
import modules.utils as utils
from pymetasploit3.msfrpc import MsfRpcClient
from modules.attack_env.metasploit import MetasploitInterface

def arguments():
    """ Get the IPv4 or CIDR address information of the scope of the assessment """
    
    # set up argparse
    parser = argparse.ArgumentParser(
        prog='Phorcys',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(utils.banner)
    )

    parser.add_argument('target', type=str, help="Scope of the Penetration Test (IPv4 Address or CIDR Notation)")
    parser.add_argument("-s", "--new_scan", dest='scan', action='store_true', 
                        help="Scan with OWASPNettacker or use pre-existing data scan data")
    parser.add_argument("-m", "--mute_banner", dest='banner', action='store_false',
                        help="Hide amazing phorcys banner")

    parser.add_argument("-i", "--iterations", dest='iterations', nargs='?', const=1, type=int,
                        default=1000, help="Define number of training iterations for RL agent (Default: 1000)")
                        
    parser.add_argument("-a", "--actions_per_target", dest='actions', nargs='?', const=1, type=int,
                        default=5, help="Define training number of actions per host that is allowed. (Default: 5)")
  
    parser.add_argument("-l", "--log", dest="logLevel", nargs='?', const=1, type=str, 
                        default='CRITICAL', help="Set the logging level - INFO or DEBUG")
                        
    args = parser.parse_args()

    if not args.logLevel in ['INFO', 'DEBUG', 'CRITICAL']:
        parser.print_help()
        sys.exit(0)
        
    if args.target:
        target = args.target
        
        if '/' in args.target:
           result = [str(ip) for ip in ipaddress.IPv4Network(target, False)]
           target = ','.join(result)
        
        return target, args

    parser.print_help()
    
    return None, None

if __name__ == '__main__':
    ip, args = arguments()


    data = utils.get_config(ip)
    loglevel = args.logLevel
    if args.banner:
        utils.print_banner()

    metasploit = MetasploitInterface(data.get('metasploit_ip'), data.get('metasploit_port'), data.get('metasploit_password'), loglevel)

    """ WORK """
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/ftp/anonymous', 21)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/ftp/ftp_login', 21)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/ftp/ftp_version', 21)
    # success, user_level, results = metasploit.run(data.get('target'), 'exploit/unix/ftp/proftpd_133c_backdoor', 21)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/smb/smb_ms17_010', 3389)
    # success, user_level, results = metasploit.run(data.get('target'), 'exploit/windows/smb/ms17_010_eternalblue', 445)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/rdp/rdp_scanner', 3389)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep', 3389)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/ssh/ssh_version', 22)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/smb/smb_version', 3389)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/smb/smb_login', 445)
    # success, user_level, results = metasploit.run(data.get('target'), 'auxiliary/scanner/ssh/ssh_login', 22)
    
    """ WON'T ERROR OUT BUT WE DON'T HAVE A HOST THAT IS VULNERABLE """
    # success, user_level, results = metasploit.run(data.get('target'), 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce', 3389)
    

    """ NEED FIXING / NEED TO BE PROPERLY SETUP"""

    """ EXPLOIT WORKS IN MSFCONSOLE BUT IT IS MAD SLOW - Reason?"""
    # success, user_level, results = metasploit.run(data.get('target'), 'exploit/windows/smb/psexec', 445)
    
    
    
    
    

    