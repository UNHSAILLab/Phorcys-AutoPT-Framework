import requests, json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

## SOME OPTION IDEAS...
"""
- wait for the netattacker api to be done scanning then.
- Also check if it is through netattacker api done
- Check time stamps to ensure its not a previous done test
"""


class NettackerInterface:
    def __init__(self, nettacker_ip, nettacker_port, apikey, target_ip, scan_method, scan_profile):
        self.nettacker_ip = nettacker_ip
        self.nettacker_port = nettacker_port
        self.apikey = apikey
        self.target_ip = target_ip
        self.scan_method = scan_method
        self.scan_profile = scan_profile

    def new_scan(self):
        """Posts a new Scan to the Nettacker API"""
        data = {'key': self.apikey, 'targets': self.target_ip, 'scan_method': self.scan_method, 'profile': self.scan_profile}

        # _url = f"https://{nettacker_ip}:{nettacker_port}/new/scan"
        url = "https://" + self.nettacker_ip + ":" + self.nettacker_port + "/new/scan"

        r = requests.post(url, data=data, verify=False)

        return json.loads(r.content)


    def get_scan_data(self):
        """Get scan data from Nettacker API"""
        data = {'key': self.apikey}

        # comprehensive All scans

        url = "https://" + self.nettacker_ip + ":" + self.nettacker_port + "/logs/get_json?host=" + self.target_ip

        r = requests.get(url, data=data, verify=False)

        return json.loads(r.content)


# descriptive One scan Port Scan, If scan_method is being set, this may be obselete

    def get_port_scan_data(self):
        """Get Port Scan data from Nettacker API"""

        data = {'key': self.apikey}

        url = "https://" + self.nettacker_ip + ":" + self.nettacker_port + "/logs/search?q=port_scan"

        r = requests.get(url, data=data, verify=False)

        # n = NettackerInterface(r.content)
        return json.loads(r.content)


