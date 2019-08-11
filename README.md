# Objective 

*   How to use vManage REST APIs to configure and monitor URL-Filtering policy on SD-WAN edge router. 

# Requirements

To use this code you will need:

* Python 3.7+
* SD-WAN edge router with device template attached.
* Configure Umbrella API Token on vManage.

# Install and Setup

Clone the code to local machine.

```
git clone https://github.com/suchandanreddy/sdwan-url-filtering-apis.git
cd sdwan-url-filtering-apis
```
Setup Python Virtual Environment (requires Python 3.7+)

```
python3.7 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Setup local environment variables to provide vManage login details and Device Template Name which is currently attached to the SD-WAN Edge router. 

Examples:

For MAC OSX and Ubuntu Environment:

```
export vmanage_host=10.10.10.10
export vmanage_port=443
export username=admin
export password=admin
export device_template_name=BR2-CSR-1000v
```

For Windows Environment:

```
set vmanage_host=10.10.10.10
set vmanage_port=443
set username=admin
set password=admin
set device_template_name=BR2-CSR-1000v
```

After setting the env variables, run the python script `configure-url-filtering.py`

# Sample Response

```
$ python3 configure-url-filtering.py 

Fetching Template uuid of BR2-CSR-1000v

Fetching feature templates associated with BR2-CSR-1000v device template

Creating URL White list

Creating URL Filtering Security policy

Creating Security Policy

security policy uuid: 408e781c-2fea-4d4a-a461-63e2b0faecb0

Device uuid: CSR-0e6b5cd8-e811-4d8b-afe9-4c397c87b19b

Fetching device csv values

Attaching new device template

Template push status is done
```
