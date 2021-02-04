import requests, json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


## SOME OPTION IDEAS...
"""
- wait for the netattacker api to be done scanning then.
- Also check if it is through netattacker api done
- Check time stamps to ensure its not a previous done test
"""

APIKEY = "8c662394ab1ff79cc14ad42dce7b93f5"

# DUMMY CODE FOR NOW----
class NetAttackerInterface:
    def __init__(self, j):
        self.json_data = json.loads(j)

    def getJSON(self):
        return self.json_data

    def __str__(self):
        return json.dumps(self.json_data, indent=4)

    def __len__(self):
        return len(self.json_data)

# data ={'key': APIKEY, 'targets': '127.0.0.1', 'scan_method': 'all', 'profile':'all'}

# r = requests.post(f'https://127.0.0.1:5000/new/scan',data=data, verify=False)
# print(r.status_code)
# print(json.dumps(json.loads(r.content), sort_keys=True, indent=4))

data = {'key': APIKEY}

# comprehensive
r = requests.get(f"https://127.0.0.1:5000/logs/get_json?host=127.0.0.1", data=data, verify=False)


obj = NetAttackerInterface(r.content)


with open('hostlog.json', 'w') as json_file:
    json.dump(obj.getJSON(), json_file, indent=4)

    
# desc
r = requests.get(f"https://127.0.0.1:5000/logs/search?q=port_scan", data=data, verify=False)

n = NetAttackerInterface(r.content)

# print(r.content)
with open('data.json', 'w') as json_file:
    json.dump(n.getJSON(), json_file, indent=4)

