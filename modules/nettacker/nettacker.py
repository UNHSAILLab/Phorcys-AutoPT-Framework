import requests, json, sys, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NettackerInterface:
    def __init__(self, nettacker_ip, nettacker_port, nettacker_key, target, scan_method='port_scan', ping_flag=True, scan_profile='', **kwargs):
        self.nettacker_ip = nettacker_ip
        self.nettacker_port = nettacker_port
        self.apikey = nettacker_key
        self.target_ip = target
        self.scan_method = scan_method
        self.ping_flag = ping_flag
        self.scan_profile = scan_profile

        self.total_hosts = 0

        self.base_url = f"https://{nettacker_ip}:{nettacker_port}"
    
    
    def get_existing_scans(self):
        data = {'key': self.apikey}
        
        total_hosts = 0
        
        for num in range(sys.maxsize):
          r = requests.get(f"{self.base_url}/results/get_list?page={num}", data=data, verify=False)
          json_data = r.json()
          
          if len(json_data) == 0: break
          
          for item in json_data:
            total_hosts = max(item.get('id'), total_hosts)
        
        return total_hosts
          


    def new_scan(self):
        """Posts a new Scan to the Nettacker API"""

        data = {
            'key': self.apikey, 
            'targets': self.target_ip, 
            'scan_method': self.scan_method, 
            'profile': self.scan_profile,
            'ping_flag': self.ping_flag
        }

        # remove keys not used.
        data = {key: value for key, value in data.items() if value}
        
        self.total_hosts = self.get_existing_scans()
        
        r = requests.post(f"{self.base_url}/new/scan", data=data, verify=False)

        return r.json()

    def get_scan_data(self):
        """Get scan data from Nettacker API, this is deprecated but here for reference"""
        data = {'key': self.apikey}

        url = f"{self.base_url}/logs/get_json?host={self.target_ip}"

        r = requests.get(url, data=data, verify=False)

        content = r.json()

        return content


    def get_port_scan_data(self, new_scan=True):
        """Get Port Scan data from Nettacker API"""

        data = {'key': self.apikey}
        
        
        # used if to wait for most recent scan results
        if new_scan:
            current_results = self.get_existing_scans()
    
            # if new scan result not in yet.
            while not current_results > self.total_hosts:
                print(f"Nettacker scan is in progress, please wait..")
                time.sleep(5)
                current_results = self.get_existing_scans()
            
            print("SUCCESS: NETTACKER SCAN FINISHED!!")
        
        final_api_json = []
        
        for num in range(sys.maxsize):
            r = requests.get(f"{self.base_url}/logs/search?q=port_scan&page={num}", data=data, verify=False)
            temp_json = r.json()
            
            if isinstance(temp_json, dict):
                if temp_json.get('status') == 'finished': break
            
            # sometimes duplicates are on multiple pages so need to check if not in list
            for host in temp_json:
                if host not in final_api_json:
                    final_api_json.append(host)
                

        return final_api_json
