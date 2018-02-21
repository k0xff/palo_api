#!/usr/bin/env python
#adds single host to address group via API
#eg: api_public_srv_group has pre-existing security policy matching that group as source.
# api_private_srv_group has security and nat policy
#Usage: ./paloaddhost.py <IPADDRESS> <REF#> ....or when ready to commit changes: ./paloaddhost.py commit

import sys
import requests
import xml.etree.ElementTree as ET
import getpass
import datetime
import socket
import re
import time
import palocheckha

requests.packages.urllib3.disable_warnings()

def commit(active_fw_ip, api_key):
    commit_url = '''https://%s/api/?type=commit&cmd=<commit></commit>&key=%s''' % (active_fw_ip, api_key)
    commit_response = requests.get(commit_url, verify=False)
    commit_xml = ET.fromstring(str(commit_response.text))
    current_time = time.strftime("%H:%M:%S")
    global job_id
    if commit_xml.attrib['status'] == 'success':
        if len(commit_xml.findtext(".//msg")) > 1:
            msg = commit_xml.findtext(".//msg")
            if msg == 'There are no changes to commit.':
                sys.exit('No changes to commit, someone else might have committed already.')
        elif len(commit_xml.findtext(".//job")) > 1:
            job_id = commit_xml.findtext(".//job")
            print "Commit commenced %s. Job ID: %s." % (current_time, job_id)
            return job_id
    if commit_xml.attrib['status'] != 'success':
        print commit_xml.attrib
        sys.exit('Having issues committing. Speak to Networks')


commit_pend = False 
if len(sys.argv) == 2 and sys.argv[1] == 'commit':
    time.sleep(1)
    commit(palocheckha.active_fw_ip, palocheckha.api_key)
    commit_pend = True

def check_commit(active_fw_ip, job_id, api_key):
    check_commit_url = '''https://%s/api/?type=op&cmd=<show><jobs><id>%s</id></jobs></show>&key=%s''' % (active_fw_ip, job_id, api_key)
    check_commit_response = requests.get(check_commit_url, verify=False)
    check_commit_xml = ET.fromstring(str(check_commit_response.text))
    if check_commit_xml.attrib['status'] == 'success':
        global commit_progress
        global commit_result
        global commit_start
        global commit_finish
        commit_progress = check_commit_xml.findtext(".//progress") #progress is percent
        commit_result = check_commit_xml.findtext(".//result") #result is PEND or OK once done
        commit_start = check_commit_xml.findtext(".//tdeq")
        commit_finish = check_commit_xml.findtext(".//tfin")
        return commit_progress
        return commit_result
        return commit_start
        return commit_finish



if commit_pend is True:
    timer = 0
    while timer <= 60:
        check_commit(palocheckha.active_fw_ip, job_id, palocheckha.api_key)
        if timer == 60:
            sys.exit('Commit timed out after 60 secs.')
        if commit_progress == '100':
            print "Commit complete. %s" % (commit_finish)
            sys.exit('Done')
        else:    
            sys.stdout.write("%s%%..." % commit_progress)
            sys.stdout.flush()
        timer+=10
        time.sleep(10)
        continue
 


if len(sys.argv) != 3:
    sys.exit('Usage: ./paloaddhost.py <IPADDRESS> <REF#> ....or when ready to commit changes: ./paloaddhost.py commit')    

ipgiven = sys.argv[1]
ticketref  = str(sys.argv[2])
if len(ticketref) > 10:
    sys.exit('Usage: ./paloaddhost.py IPADDRESS REF#\nPlease re-try with ticket reference number < 10 chars')
ipgiven_hyphen = ipgiven + '-32' 
ipgiven_cidr = ipgiven + '/32'

#validate IP
def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False
    return True

if is_valid_ipv4_address(ipgiven) == False:
    sys.exit('Not a valid IP')


#determining whether IP provided is valid.
#dictates which Palo address group the host is placed into
#public = no NAT, private will be NAT'd

valid_public = False
valid_private = False

#below regex is matching our /16 (example prefix below obscufated)
if re.match( r'^129\.129\.', ipgiven):
    valid_public = True

#checking whether RFC1918
if re.match( r'^10\.', ipgiven):
    valid_private = True
if re.match( r'^172\.(1[6-9]|2[0-9]|3[0-1])', ipgiven):
    valid_private = True
if re.match( r'^192\.168\.', ipgiven):
    valid_private = True


#placing into object group
#public = no NAT, private will be NAT'd
if valid_public is True:
    address_group = 'api_public_srv_group' #no nat
if valid_private is True:
    address_group = 'api_private_srv_group'
    

#address object description for audit trail of who added host/date/ticket ref
userid = getpass.getuser()
date = str(datetime.date.today()).replace('-','')
desc = date + '_' + userid + '_' + ticketref


#list of objects
check_obj_url = "https://%s//api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address&key=%s" % (palocheckha.active_fw_ip, palocheckha.api_key)
check_obj_response = requests.get(check_obj_url, verify=False)
check_obj_xml = ET.fromstring(str(check_obj_response.text))

#check if object exists, create if it doesnt

object_exists = False

for x in check_obj_xml.iter("entry"):
    if x.attrib['name'] == ipgiven_hyphen:
        object_exists = True
        print 'Existing object name found: %s' % (ipgiven_hyphen)
        if x[0].text == ipgiven_cidr:
            print 'IP Address: %s confirmed. Re-using' % (ipgiven_cidr)
            #reuse_object = True


#create object
if object_exists is False:
    add_obj_url = '''https://%s/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address&element=<entry name="%s"><ip-netmask>%s</ip-netmask><description>%s</description></entry>&key=%s''' % (palocheckha.active_fw_ip , ipgiven_hyphen, ipgiven_cidr, desc, palocheckha.api_key)
    add_obj_response = requests.get(add_obj_url, verify=False)
    add_obj_xml = ET.fromstring(str(add_obj_response.text))
    #checking
    if add_obj_xml.attrib['status'] == 'success':
            print 'Address object created successfully'
    if add_obj_xml.attrib['status'] != 'success':
            print add_obj_xml.attrib
            sys.exit('Something up with object creation, bailing')

#ADD ADDRESS OBJECT TO GROUP:
add_ag_url = '''https://%s/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']&element=<static><member>%s</member></static>&key=%s''' % (palocheckha.active_fw_ip , address_group, ipgiven_hyphen, palocheckha.api_key)
add_ag_response = requests.get(add_ag_url, verify=False)
add_ag_xml = ET.fromstring(str(add_ag_response.text))

if add_ag_xml.attrib['status'] == 'success':
    print "Added to %s address group successfully.\nWhen ready, run './paloaddhost.py commit' to take effect." % (address_group)
if add_ag_xml.attrib['status'] != 'success':
    print add_ag_xml.attrib
    sys.exit('Something up with adding to address group, bailing')

