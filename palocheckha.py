#!/usr/bin/env python
#Used by the other python scripts to determine active HA unit and key.

import sys
import requests
import xml.etree.ElementTree as ET

requests.packages.urllib3.disable_warnings()

#generate API key, per firewall.
##https://SECONDARYFWIP/esp/restapi.esp?type=keygen&user=USER&password=PASSWORD
SECFW_api_key = "FOO="
PRIFW_api_key = "BAR="

def checkha():
    #check HA status
    try:
        ha_url = "https://SECONDARYFWIP//api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=%s" % (SECFW_api_key)
        haresponse = requests.get(ha_url, verify=False, timeout=2)
        haxml = ET.fromstring(str(haresponse.text))
        if haxml.attrib['status'] == 'success' and haxml.findtext(".//state") == 'passive':
            active_fw_ip = 'PRIMARYFWIP'
            api_key = PRIFW_api_key
            return active_fw_ip, api_key
        if haxml.attrib['status'] == 'success' and haxml.findtext(".//state") == 'active':
            active_fw_ip = 'SECONDARYFWIP'
            api_key = SECFW_api_key
            return active_fw_ip, api_key
        if haxml.attrib['status'] != 'success':
            print haxml.attrib
            sys.exit('Somethings up with API or HA on firewalls. Speak to Networks')
    except requests.exceptions.ConnectTimeout as e:
        print 'Issue connecting to SECONDARYFWIP, trying PRIMARYFWIP'
        ha_url = "https://PRIMARYFWIP//api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>&key=%s" % (PRIFW_api_key)
        haresponse = requests.get(ha_url, verify=False, timeout=2)
        haxml = ET.fromstring(str(haresponse.text))
        if haxml.attrib['status'] == 'success' and haxml.findtext(".//state") == 'passive':
            active_fw_ip = 'SECONDARYFWIP'
            api_key = SECFW_api_key
            return active_fw_ip
        if haxml.attrib['status'] == 'success' and haxml.findtext(".//state") == 'active':
            active_fw_ip = 'PRIMARYFWIP'
            api_key = PRIFW_api_key
            return active_fw_ip, api_key
        if haxml.attrib['status'] != 'success':
            print haxml.attrib
            sys.exit('Somethings up with API or HA on firewalls. Speak to Networks')


active_fw_ip, api_key = checkha()

if __name__ == '__main__':
    print 'This script is used by others to determine which unit is active, and the respective API key.'
    print 'Active FW: %s\n' % (active_fw_ip)
