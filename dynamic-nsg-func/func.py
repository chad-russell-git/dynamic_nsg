#
# oci-vault-get-secret-python version 1.0.
#
# Copyright (c) 2020 Oracle, Inc.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl.
#

import io
import json
import base64
import oci
import logging
import hashlib
import urllib.request

from fdk import response
from oci.core.models import add_network_security_group_security_rules_details

#working
def get_nsg_security_rules(nsg_ocid):
    nsgs = ""
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        
          
        client = oci.core.VirtualNetworkClient({}, signer=signer)
        
        nsgs = client.list_network_security_group_security_rules(nsg_ocid)
        nsgs = [[v.id, v.description, v.direction, v.destination] for v in nsgs.data]


        
    except Exception as ex:
        print("ERROR: failed to retrieve the secret content", ex, flush=True)
        raise
    return {"nsg security rules": nsgs}

#in process - took out blocked_ip list argument from next line for now for testing
def add_nsg_security_rules(nsg_ocid, blockedip):
    #blockedip = ""
    #blockediplist = []
    add_network_security_group_security_rules_details = ""
    signer = oci.auth.signers.get_resource_principals_signer()
    try:
        
          
        core_client = oci.core.VirtualNetworkClient({}, signer=signer)
        # https://docs.oracle.com/en-us/iaas/tools/python-sdk-examples/2.46.0/core/add_network_security_group_security_rules.py.html
        #nsg_add_security_rules = client.add_network_security_group_security_rules(nsg_ocid, add_network_security_group_security_rules_details=)
        #nsg_add_security_rules = [[v.id, v.description, v.direction, v.destination] for v in nsg_add_security_rules.data]

        add_network_security_group_security_rules_response = core_client.add_network_security_group_security_rules(
        network_security_group_id=nsg_ocid,
        add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
        security_rules=[
            oci.core.models.AddSecurityRuleDetails(
                direction="INGRESS",
                protocol="6",
                description="EXAMPLE-description-Value",
                destination="EXAMPLE-destination-Value",
                destination_type="SERVICE_CIDR_BLOCK",
                is_stateless=True,
                source=blockedip + "/" + "32",
                source_type="CIDR_BLOCK",
                tcp_options=oci.core.models.TcpOptions(
                    destination_port_range=oci.core.models.PortRange(
                            max=625,
                            min=32),
                    source_port_range=oci.core.models.PortRange(
                        max=783,
                        min=58)),
                #udp_options=oci.core.models.UdpOptions(
                    #destination_port_range=oci.core.models.PortRange(
                        #max=706,
                        #min=113),
                    #source_port_range=oci.core.models.PortRange(
                        #max=175,
                        #min=354)
                        )]))

        
    except Exception as ex:
        print("ERROR: failed to set security rules", ex, flush=True)
        raise
    return {"nsg add security rules": "hopefully the rules were added.   Time to check the OCI console."}

#working
def pull_ip_block_list(target_url, nsg_ocid):
    
    for line in urllib.request.urlopen(target_url):
        logging.getLogger().info("blocked ips = " + line.decode('utf-8'))
        blockedip = line.decode('utf-8')
        blockedip = blockedip.strip()
        add_nsg_security_rules(nsg_ocid, blockedip)
        

#working
def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("function start")

    secret_ocid = secret_type = resp = ""
    try:
        cfg = dict(ctx.Config())
        nsg_ocid = cfg["nsg_ocid"]
        target_url = cfg["target_url"]
        logging.getLogger().info("nsg ocid = " + nsg_ocid)

    except Exception as e:
        print('ERROR: Missing configuration keys, nsg ocid', e, flush=True)
        raise

    
    resp = get_nsg_security_rules(nsg_ocid)
    #added_rule = add_nsg_security_rules(nsg_ocid)
    #logging.getLogger().info("nsg ocid = " + added_rule)

    #calls function to print blocked ip's to FN logging stream in OCI Logging
    blocked_addresses = pull_ip_block_list(target_url, nsg_ocid)

    logging.getLogger().info("function end")
    return response.Response(
        ctx, 
        response_data=resp,
        headers={"Content-Type": "application/json"}
    )