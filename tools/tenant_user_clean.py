#!/usr/bin/python

# Script to delete the users and tenants not cleaaned up due to tempest test failures
# Source the credentials saved in the openrc file or set the following environment variables before executing the script
#  export SERVICE_TOKEN=<admin_token>
#  export SERVICE_ENDPOINT=<http://host:port/v2.0/>

# To execute 
# tools/tenant_user_clean.py

import subprocess
import re

keystone = "/usr/bin/keystone"
# List users in Keystone and delete the ones left behind by failed tempest tests
output = subprocess.check_output([keystone,'user-list'])
tenant_id_list = []
for line in output.splitlines():
    column = line.split('|')
    if len(column) >= 4:
        m = re.search("tempest_test_user_[0-9]*", column[4]) 
        n = re.search(".*tempest-(alt-)?user-*[0-9]*", column[4])
        if m is not None or n is not None or column[4].strip() == 'user_1234':
            try:
                result = subprocess.check_output([keystone,'user-delete',column[1].strip()])
                print "Deleted user" + column[4]
            except:
                print "Error while deleting user" + column[4]

# List tenants in Keystone and delete the ones left behind by failed tempest tests
tenant_list_output = subprocess.check_output([keystone,'tenant-list'])
for line in tenant_list_output.splitlines():
    column = line.split('|')
    if len(column) >= 3:
        m = re.search("tempest_test_tenant_[0-9]*", column[2])
        n = re.search(".*tempest-(alt-)?tenant-*[0-9]*", column[2])
        if m is not None or n is not None:
            try:
                result = subprocess.check_output([keystone,'tenant-delete',column[1].strip()])
                print "Deleted tenant" + column[2]
            except:
                print "Error while deleting tenant" + column[2]

