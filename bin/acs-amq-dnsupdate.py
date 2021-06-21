#!/usr/bin/env -S python3 -u
#
# /usr/local/bin/acs-amq-dnsupdate.py
#
import pika
import json
import sys
import os
import re
import sqlite3
import dns.tsigkeyring
import dns.update
import ipaddress
# pip install cs # https://github.com/exoscale/cs
from cs import CloudStack

import yaml
import logging

global dns_map

def main():
    
    work_dir = os.path.abspath(os.getcwd())

    logging.basicConfig(filename=f'{work_dir}/log/dnsupdate.log', encoding='utf-8', level=logging.DEBUG)

    with open(f'{work_dir}/conf/param.yml') as f:
        param = yaml.safe_load(f)

    for param_key, param_value in param.items():
        if param_key in os.environ:
            param[param_key] = os.getenv(param_key)

    dns_map = param['DNS_MAP']

    cs = CloudStack(endpoint=param['ACS_ENDPOINT'],
            key=param['ACS_APIKEY'],
            secret=param['ACS_SECRETKEY'])

    con = sqlite3.connect(param['SQLITE_DB'])
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS entries
            (vm_uuid text, hostname text, network_domain text, network_uuid text, a text, aaaa text)''')
    #cur.execute("INSERT INTO stocks VALUES ('2006-01-05','BUY','RHAT',100,35.14)")
    con.commit()
    con.close()

    credentials = pika.PlainCredentials(param['AMQ_USERNAME'], param['AMQ_PASSWORD'])
    parameters = pika.ConnectionParameters(param['AMQ_HOSTNAME'],
            int(param['AMQ_PORT']),
            '/',
            credentials)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue
    channel.queue_bind(exchange=param['AMQ_EXCHANGE'],
            routing_key='#',
            queue=queue_name)

    def callback(ch, method, properties, body):
        rklist = method.routing_key.split('.')
        #management-server.AsyncJobEvent.complete.VirtualMachine.bc1475fd-b1bc-41be-9766-29e46a830729
        if (rklist[0] == 'management-server' and
            rklist[1] == 'AsyncJobEvent' and
            rklist[2] == 'complete' and
            rklist[3] == 'VirtualMachine'):
                uuid = rklist[4]
                print('uuid: %s' % uuid)
                #try:
                bstring = body.decode('ascii')
                blist = json.loads(bstring)
                if ('instanceUuid' in blist and
                        'commandEventType' in blist and
                        'status' in blist and
                        blist['instanceUuid'] == uuid and
                        blist['status'] == 'SUCCEEDED'):

                    # DESTROY
                    if (blist['commandEventType'] == 'VM.DESTROY'):
                        print('DESTROY VM WITH UUID: %s' % uuid)
                        try:
                            con = sqlite3.connect(param['SQLITE_DB'])
                            cur = con.cursor()
                            cur.execute("SELECT vm_uuid,hostname,network_domain,network_uuid,a,aaaa FROM entries WHERE vm_uuid = '%s'" % uuid )
                            for row in cur:
                                removerecords(row[0], row[1], row[2], row[4], row[5])
                            cur.execute("DELETE FROM entries WHERE vm_uuid = '%s'" % uuid )
                            con.commit()
                            con.close()
                        except:
                            print(f'[ERROR] Unable to remove records for UUID: {uuid}')
                            logging.error(f'Unable to remove records for UUID: {uuid}')

                    # CREATE
                    if (blist['commandEventType'] == 'VM.CREATE' and
                            'jobResult' in blist):
                        print('CREATE VM WITH UUID: %s' % uuid)
                        vms = cs.listVirtualMachines(id=uuid, fetch_list=True)
                        if (len(vms) == 1):
                            vm = vms[0]
                            hostname = vm['name']
                            domain = ''
                            ipaddress = ''
                            ip6address = ''
                            for nic in vm['nic']:
                                if ('type' in nic and nic['type'] == 'Shared' and
                                        'isdefault' in nic and nic['isdefault'] == True and
                                        'networkid' in nic):
                                    if ('ipaddress' in nic):
                                        ipaddress = nic['ipaddress']
                                    if ('ip6address' in nic):
                                        ip6address = nic['ip6address']
                                    networks = cs.listNetworks(id=nic['networkid'], fetch_list=True)
                                    if (len(networks) == 1):
                                        network = networks[0]
                                        if ('networkdomain' in network):
                                            domain = network['networkdomain']
                                if validate_fqdn(hostname + '.' + domain):
                                    try:
                                        con = sqlite3.connect(param['SQLITE_DB'])
                                        cur = con.cursor()
                                        cur.execute("INSERT INTO entries VALUES ('%s','%s','%s','%s','%s','%s')" %
                                                (uuid, hostname, domain, nic['networkid'], ipaddress, ip6address))
                                        con.commit()
                                        con.close()
                                        addrecords(uuid, hostname, domain, ipaddress, ip6address)
                                    except:
                                        print(f'[ERROR] Unable to add records for UUID: {uuid}')
                                        logging.error(f'Unable to add records for UUID: {uuid}')
                                else:
                                    print(f'[ERROR] FQDN does not validate. Not adding records ro UUID: {uuid}')
                                    logging.error(f'FQDN does not validate. Not adding records ro UUID: {uuid}')

    print('Listening for AMQ messages on amq://%s:%s/%s. To exit press CTRL+C' %
            (param['AMQ_HOSTNAME'], param['AMQ_PORT'], param['AMQ_EXCHANGE']))
    channel.basic_consume(callback,
            queue=queue_name,
            no_ack=True)

    channel.start_consuming()

def dnscfg():
    try:
        with open(dns_map) as json_file:
            cfg = json.load(json_file)
    except:
        print(f'[ERROR] Unable to parse DNS Configuration from {dns_map}.')
        logging.error(f'Unable to parse DNS Configuration from {dns_map}.')
        
        cfg = {'tsigkeys': {}, 'zones': {}, }
    return cfg

def validate_fqdn(dn):
    if dn.endswith('.'):
        dn = dn[:-1]
    if len(dn) < 1 or len(dn) > 253:
        return False
    ldh_re = re.compile('^[a-z0-9-]{2,63}$', re.IGNORECASE)
    return all(ldh_re.match(x) for x in dn.split('.'))

# get hardcoded /64 DNS PTR Zone from IPv6
def ptr6zone64(self):
    reverse_chars = self.exploded[::-1].replace(':', '')
    rev64 = reverse_chars[-16:]
    return '.'.join(rev64) + '.ip6.arpa'

# get hardcoded /16 DNS PTR Zone for IPv4
def ptr4zone24(self):
    list=self.split('.')
    del list[0:2]
    return list.join('.')

# Remove Nameserver Records
def removerecords(uuid='', hostname='', domain='', ipaddress='', ip6address=''):
    print(f'Remove records for VM. uuid={uuid}, hostname={hostname}, domain={domain}, ipaddress={ipaddress}, ip6address={ip6address}')
    logging.info(f'Remove records for VM. uuid={uuid}, hostname={hostname}, domain={domain}, ipaddress={ipaddress}, ip6address={ip6address}')

    ip6 = ipaddress.ip_address(ip6address)
    ptr6zone = ptr6zone64(ip6)
    ip4 = ipaddress.ip_address(ipaddress)
    ptr4zone = ptr4zone24(ipv4.reverse_pointer)
    cfg = dnscfg()
    for zone in [ domain, ptr4zone, ptr6zone ]:
        if zone in cfg['zones']:
            for arhash in cfg['zones'][zone]:
                if ('tsigkey' in arhash) and (arhash['tsigkey'] in cfg['tsigkeys']):
                    tsighash = cfg['tsigkeys'][arhash['tsigkey']]
                    if 'RR' in arhash:
                        for rrs in arhash['RR']:
                            print(f'remove {rrs} record for {hostname} in zone {zone}')
                            logging.info(f'remove {rrs} record for {hostname} in zone {zone}')


# Add Nameserver Records
def addrecords(uuid='', hostname='', domain='', ipaddress='', ip6address=''):
    print('Add records for VM. uuid=%s, hostname=%s, domain=%s, ipaddress=%s, ip6address=%s' % (uuid, hostname, domain, ipaddress, ip6address))
    logging.info(f'ADD records for VM. uuid={uuid}, hostname={hostname}, domain={domain}, ipaddress={ipaddress}, ip6address={ip6address}')

    ip6 = ipaddress.ip_address(ip6address)
    ptr6zone = ptr6zone64(ip6)
    ip4 = ipaddress.ip_address(ipaddress)
    ptr4zone = ptr4zone24(ipv4.reverse_pointer)
    print('Zones: domain: %s, ptr4zone: %s, ptr6zone: %s' % (domain, ptr4zone, ptr6zone))
    cfg = dnscfg()
    print('%r' % cfg)
    for zone in [ domain, ptr4zone, ptr6zone ]:
        if zone in cfg['zones']:
            for arhash in cfg['zones'][zone]:
                if ('tsigkey' in arhash) and (arhash['tsigkey'] in cfg['tsigkeys']):
                    tsighash = cfg['tsigkeys'][arhash['tsigkey']]
                    if 'RR' in arhash:
                        for rrs in arhash['RR']:
                            print('add %s record for %host in zone %s' % (rrs, hostname, zone))
                            logging.info(f'remove {rrs} record for {hostname} in zone {zone}')

#
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

