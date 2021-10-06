import vaulthelper # <-- This is the attached Layer which includes functions related to Vault access
import requests
import urllib3
import logging
import os
from tempfile import NamedTemporaryFile

requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL' # <-- For PuppetDB compatibility

logger = logging.getLogger()
logger.setLevel(logging.INFO)
region = os.environ['AWS_REGION']


def op5_commit_changes(op5_url, op5_user, op5_pass):
    r = requests.get(op5_url + '/api/config/change', auth=(op5_user, op5_pass), verify=False)
    logger.info('Attempting to apply changes: {}'.format(r.json()))
    r = requests.post(op5_url + '/api/config/change', auth=(op5_user, op5_pass), verify=False)
    if r.status_code == 200:
        logger.info('OP5 changes executed successfully')
    else:
        logger.error('Error applying changes: {}'.format(r.text))


def op5_verify(node_list, op5_url, op5_user, op5_pass):
    logger.info('Verifying OP5 integration')
    existing_hosts = []
    nodes_to_add = []
    host_query = requests.get(op5_url + '/api/config/host', auth=(op5_user, op5_pass), verify=False)
    for host in host_query.json():
        existing_hosts.append(host['name'])
    #logger.info('Found {} hosts in OP5: {}'.format(len(existing_hosts), existing_hosts))
    for node in node_list:
        if node['fqdn'] not in existing_hosts:
            logger.info('{} node {} ({}) will be enrolled'.format(node['osfamily'], node['fqdn'], node['ipaddress']))
            logger.info('Discovered packages for {}: {}'.format(node['fqdn'], node['package_info']))
            nodes_to_add.append(node)
        else:
            logger.info('{} already enrolled'.format(node['fqdn']))
    return nodes_to_add
        

def op5_enroll_nodes(nodes_to_add, op5_url, op5_user, op5_pass):
    for node in nodes_to_add:
        logger.info('Configuring OP5 integration for: {}'.format(node['fqdn']))
        if node['osfamily'] == 'windows':
            host_template = 'ET-Windows-Template'
        else:
            host_template = 'ET-Linux-Template'
        ### LAYER ADDITIONAL HOSTGROUPS HERE DEPENDING ON INSTALLED PACKAGES ###
        ### USE PATCH METHOD ON TOP OF THIS API CALL TO ADD HOSTGROUP ARRAY ###
        payload = {
            'host_name': node['fqdn'],
            'address': node['ipaddress'],
            'template': host_template
            }
        r = requests.post(op5_url + '/api/config/host', auth=(op5_user, op5_pass), json=payload, verify=False)
        if r.status_code != 201:
            logger.error('{} Error enrolling {}: {}'.format(r.status_code, node['fqdn'], r.text))
        else:
            logger.info('{} Successfully enrolled node {}'.format(r.status_code, node['fqdn']))


def get_pdb_nodes(pdb_url, puppet_env):
    node_query = '/pdb/query/v4/nodes?query=["=", "catalog_environment", "{}"]'.format(puppet_env)
    r = requests.get(pdb_url + node_query, verify='/tmp/ca_cert.txt', cert=('/tmp/cert.txt', '/tmp/key.txt'))
    nodes = []
    for node in r.json():
        nodes.append(node['certname'])
    return nodes


def get_pdb_facts(nodes, pdb_url, puppet_env):
    node_list = []
    resources = []
    node_data = {}
    fact_query = '/pdb/query/v4/environments/{}/facts'.format(puppet_env)
    resource_query = '/pdb/query/v4/environments/{}/resources'.format(puppet_env)
    facts_to_gather = [ 'fqdn', 'osfamily', 'operatingsystem', 'ipaddress', 'package_info' ]
    for node in nodes:
        node_data = {}
        payload = '["=", "certname", "{}"]'.format(node)
        payload
        for fact in facts_to_gather:
            r = requests.get(pdb_url + fact_query + '/' + fact + '?query={}'.format(payload), verify='/tmp/ca_cert.txt', cert=('/tmp/cert.txt', '/tmp/key.txt'))
            try:
                node_data.update({fact: r.json()[0]['value']})
            except:
                logger.error('Index not found for {} on {}'.format(fact, node))
        r = requests.get(pdb_url + resource_query + '?query={}'.format(payload), verify='/tmp/ca_cert.txt', cert=('/tmp/cert.txt', '/tmp/key.txt'))
        for resource in r.json():
            if 'Profile' in resource['title']:
                resources.append(resource['title'])
        node_data.update({'resources': resources})
        node_list.append(node_data)
    return node_list
    

        

def lambda_handler(event, context):
    puppet_env = 'ee_op5'
    pdb_url = 'https://pptdb:8081'
    vault_role = 'eevault-iam-eea-op5'

    op5_url = 'https://' + vaulthelper.get_secret(vault_role, 'eea-op5/op5', 'ip')
    op5_user = vaulthelper.get_secret(vault_role, 'eea-op5/op5', 'user')
    op5_pass = vaulthelper.get_secret(vault_role, 'eea-op5/op5', 'pass')

    cert_data = vaulthelper.get_certificate(vault_role, 'lambda.io')
    ca_cert_list = cert_data['data']['ca_chain']

    separator = '\n'
    with open('/tmp/ca_cert.txt', 'w') as f: 
        f.write(separator.join(ca_cert_list))
    f.close()
    with open('/tmp/cert.txt', 'w') as f:
        f.write(cert_data['data']['certificate'])
    f.close()
    with open('/tmp/key.txt', 'w') as f:
        f.write(cert_data['data']['private_key'])
    f.close() 

    nodes = get_pdb_nodes(pdb_url, puppet_env)
    node_list = get_pdb_facts(nodes, pdb_url, puppet_env)
    nodes_to_add = op5_verify(node_list, op5_url, op5_user, op5_pass)

    if len(nodes_to_add) > 0:
        op5_enroll_nodes(nodes_to_add, op5_url, op5_user, op5_pass)
        op5_commit_changes(op5_url, op5_user, op5_pass)
    else:
        logger.info('Nothing to do')
