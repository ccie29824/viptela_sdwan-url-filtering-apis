import requests
import json
import os

from jinja2 import Template
from requests.packages.urllib3.exceptions import InsecureRequestWarning

vmanage_host = os.environ.get("vmanage_host")
vmanage_port = os.environ.get("vmanage_port")
username = os.environ.get("username")
password = os.environ.get("password")
device_template_name = os.environ.get("device_template_name")


if vmanage_host is None or vmanage_port is None or username is None or password is None or device_template_name is None :
    print("For Windows Workstation, vManage details must be set via environment variables using below commands")
    print("set vmanage_host=198.18.1.10")
    print("set vmanage_port=443")
    print("set username=admin")
    print("set password=admin")
    print("set device_template_name=BR2-CSR-1000v")
    print("For MAC OSX Workstation, vManage details must be set via environment variables using below commands")
    print("export vmanage_host=198.18.1.10")
    print("export vmanage_port=443")
    print("export username=admin")
    print("export password=admin")
    print("export device_template_name=BR2-CSR-1000v")
    exit()

requests.packages.urllib3.disable_warnings()

class rest_api_lib:
    def __init__(self, vmanage_host,vmanage_port, username, password):
        self.vmanage_host = vmanage_host
        self.vmanage_port = vmanage_port
        self.session = {}
        self.login()

    def login(self):

        """Login to vmanage"""

        base_url = 'https://%s:%s/'%(vmanage_host,vmanage_port)

        login_action = '/j_security_check'

        #Format data for loginForm
        login_data = {'j_username' : username, 'j_password' : password}

        #URL for posting login data
        login_url = base_url + login_action
        
        sess = requests.session()

        #If the vmanage has a certificate signed by a trusted authority change verify to True

        login_response = sess.post(url=login_url, data=login_data, verify=False)

        if b'<html>' in login_response.content:
            print ("Login Failed")
            exit(0)

        self.session[vmanage_host] = sess

    def get_request(self, mount_point):
        """GET request"""
        url = "https://%s:%s/dataservice/%s"%(self.vmanage_host, self.vmanage_port, mount_point)
        #print(url)
      
        response = self.session[self.vmanage_host].get(url, verify=False)
        
        return response

    def post_request(self, mount_point, payload, headers={'Content-type': 'application/json', 'Accept': 'application/json'}):
        """POST request"""
        url = "https://%s:%s/dataservice/%s"%(self.vmanage_host, self.vmanage_port, mount_point)
        #print(url)
        payload = json.dumps(payload)
        #print (payload)

        response = self.session[self.vmanage_host].post(url=url, data=payload, headers=headers, verify=False)
        #print(response.text)
        #exit()
        #data = response
        return response

    def put_request(self, mount_point, payload, headers={'Content-type': 'application/json', 'Accept': 'application/json'}):
        """POST request"""
        url = "https://%s:%s/dataservice/%s"%(self.vmanage_host, self.vmanage_port, mount_point)
        #print(url)
        payload = json.dumps(payload)
        #print (payload)

        response = self.session[self.vmanage_host].put(url=url, data=payload, headers=headers, verify=False)
        #print(response.text)
        #exit()
        #data = response
        return response




vmanage_session = rest_api_lib(vmanage_host, vmanage_port, username, password)

#Fetching list of device templates

template_id_response = vmanage_session.get_request("template/device")

if template_id_response.status_code == 200:
    items = template_id_response.json()['data']
    template_found=0
    print("\nFetching Template uuid of %s"%device_template_name)
    for item in items:
        if item['templateName'] == device_template_name:
            device_template_id = item['templateId']
            template_found=1
            break
    if template_found==0:
        print("\nDevice Template is not found")
        exit()
else:
    print("\nError fetching list of templates")
    exit()

#Fetching feature templates associated with Device template. 

print("\nFetching feature templates associated with %s device template"%device_template_name)

template_response = vmanage_session.get_request("template/device/object/%s"%(device_template_id))

if template_response.status_code == 200:
    feature_template_ids=template_response.json()
else:
    print("\nError fetching feature template ids")
    exit()

#Create URL white list 

print("\nCreating URL White list")

'''url_list = ['outlook.com', 'linkedin.com', 'ntp.ubuntu.com']

template = Template({ "name": "email-social-network-api-call",
                      "description": "email-social-network-api-call",
                      "type": "urlWhiteList",
                      "entries": [{% for url in data %}
                                  {"pattern": "{{url}}"},
                                  {% endfor %}]})

whitelist_payload = template.render(data=url_list)'''

whitelist_payload = { "name":"email-social-network-api-call", 
                      "description":"email-social-network-api-call",
                      "type":"urlWhiteList",
                      "entries":[{"pattern":"outlook.com"},{"pattern":"linkedin.com"},{"pattern":"facebook.com"}
                      ]
                    }

url_white_list = vmanage_session.post_request("template/policy/list/urlwhitelist",whitelist_payload)

if url_white_list.status_code==200:
    white_listid = url_white_list.json()["listId"]
else:
    print("\nError creating URL White list\n")
    print(url_white_list.text)
    exit()

#Create URL Filtering Policy

print("\nCreating URL Filtering Security policy")

urlfiltering_policy_name="BR2-VPN10-URL-Filtering-API-Call"

url_filtering_payload = {"name": urlfiltering_policy_name,
                        "type": "urlFiltering",
                        "description": urlfiltering_policy_name,
                        "definition": {
                            "webCategoriesAction": "block",
                            "webCategories": [
                            "abortion",
                            "abused-drugs",
                            "adult-and-pornography",
                            "alcohol-and-tobacco",
                            "auctions",
                            "bot-nets",
                            "cheating",
                            "confirmed-spam-sources",
                            "cult-and-occult",
                            "dating",
                            "dead-sites",
                            "dynamic-content",
                            "gambling",
                            "games",
                            "gross",
                            "hacking",
                            "hate-and-racism",
                            "illegal",
                            "keyloggers-and-monitoring",
                            "malware-sites",
                            "marijuana",
                            "nudity",
                            "personal-sites-and-blogs",
                            "philosophy-and-political-advocacy",
                            "phishing-and-other-frauds",
                            "private-ip-addresses",
                            "questionable",
                            "real-estate",
                            "religion",
                            "search-engines",
                            "sex-education",
                            "shareware-and-freeware",
                            "social-network",
                            "shopping",
                            "spam-urls",
                            "spyware-and-adware",
                            "streaming-media",
                            "swimsuits-and-intimate-apparel",
                            "uncategorized",
                            "unconfirmed-spam-sources",
                            "violence",
                            "weapons",
                            "news-and-media"
                            ],
                            "webReputation": "high-risk",
                            "urlWhiteList": {
                            "ref": white_listid
                            },
                            "blockPageAction": "text",
                            "blockPageContents": "&lt;h3&gt;Access to the requested page has been denied&lt;/h3&gt;&lt;p&gt;Please contact your Network Administrator&lt;/p&gt;",
                            "enableAlerts": True,
                            "alerts": [
                            "blacklist",
                            "whitelist",
                            "categories-reputation"
                            ],
                            "logging": [],
                            "targetVpns": ["10"]
                        }
                        }

url_filtering_response = vmanage_session.post_request("template/policy/definition/urlfiltering",url_filtering_payload)

if url_filtering_response.status_code==200:
    url_filtering_uuid=url_filtering_response.json()["definitionId"]
else:
    print("\nError creating URL filtering policy\n")
    print(url_filtering_response.text)
    exit()

#Creating Security Policy

print("\nCreating Security Policy")

security_policy_name="BR2-Security-Policy-API"

security_payload = {"policyDescription": security_policy_name,
           "policyType": "feature",
           "policyName": security_policy_name,
           "policyUseCase": "custom",
           "policyDefinition": {
           "assembly": [
                {
                "definitionId": url_filtering_uuid,
                "type": "urlFiltering"
                }
            ],
            "settings": { "failureMode": "open"}
            },
            "isPolicyActivated": False
            }

security_policy_res = vmanage_session.post_request("template/policy/security/",security_payload)

if not (security_policy_res.status_code == 200):
    print("\nCreating security policy failed")

#Fetching Security Policy uuid

security_policy_uuid_res = vmanage_session.get_request("template/policy/security/")

if security_policy_uuid_res.status_code == 200:
    items = security_policy_uuid_res.json()['data']
    for item in items:
        if item['policyName'] == security_policy_name:
            security_policy_uuid = item['policyId']
            break
else:
    print("\nFetching Security Policy uuid failed\n")
    print(security_policy_uuid_res.text)
    
print("\nsecurity policy uuid: %s"%security_policy_uuid)

#Edit Device Template

payload = {"templateId":device_template_id,"templateName":device_template_name,
           "templateDescription":feature_template_ids["templateDescription"],"deviceType":feature_template_ids["deviceType"],
           "configType":"template","factoryDefault":False,
           "policyId":feature_template_ids["policyId"],
           "featureTemplateUidRange":[],"connectionPreferenceRequired":True,
           "connectionPreference":True,"policyRequired":True,
           "generalTemplates":feature_template_ids["generalTemplates"],
            "securityPolicyId":security_policy_uuid}

device_template_edit_res = vmanage_session.put_request("template/device/%s"%device_template_id,payload)

if device_template_edit_res.status_code == 200:
    device_uuid = device_template_edit_res.json()['data']['attachedDevices'][0]['uuid']
    template_pushid = device_template_edit_res.json()['data']['processId']
else:
    print("\nError editing device template\n")
    print(device_template_edit_res.text)

print("\nDevice uuid: %s"%device_uuid)

# Fetching Device csv values

print("\nFetching device csv values")

payload = {"templateId":device_template_id,
           "deviceIds":[device_uuid],
           "isEdited":False,"isMasterEdited":False}

device_csv_res = vmanage_session.post_request("template/device/config/input/",payload)

if device_csv_res.status_code == 200:
    device_csv_values = device_csv_res.json()['data'][0]
else:
    print("\nError getting device csv values\n")
    print(device_csv_res.text)

# Attaching new Device template

print("\nAttaching new device template")

payload = {"deviceTemplateList":[{"templateId":device_template_id,
           "device":[device_csv_values],
           "isEdited":True,"isMasterEdited":False}]}

attach_template_res = vmanage_session.post_request("template/device/config/attachfeature",payload)

if attach_template_res.status_code == 200:
    attach_template_pushid = attach_template_res.json()['id']
else:
    print("\nattaching device template failed\n")
    print(attach_template_res.text)
    exit()

# Fetch the status of template push

while(1):
    template_status_res = vmanage_session.get_request("device/action/status/%s"%attach_template_pushid)
    if template_status_res.status_code == 200:
        if template_status_res.json()['summary']['status'] == "done":
            print("\nTemplate push status is done")
            break
        else:
            continue
    else:
        print("\nFetching template push status failed\n")
        print(template_status_res.text)
        exit()

