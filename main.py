from Nettacker import *

nettacker_ip = "127.0.0.1"
nettacker_port = "5000"
apikey = "3f93b882fe3fae98e942ca7fd78744a0"
target_ip = "127.0.0.1"
scan_method = "all"
scan_profile = "all"

obj = NettackerInterface(nettacker_ip, nettacker_port, apikey, target_ip, scan_method, scan_profile)
var = obj.new_scan()
print(var)