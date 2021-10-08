#!/usr/bin/env -S python3 -u
#
# /usr/local/bin/acs-amq-dnsupdate.py
#
# Fixed network-layout is assumed:
#   IPv6 are assumed to be /64
#   IPv4 are assumed to be /16
#
import pika
import json
import sys
import os
import re
import sqlite3
# apt install python3-dnspython
import dns.tsigkeyring
import dns.update
import dns.query
import ipaddress
# pip install cs # https://github.com/exoscale/cs
from cs import CloudStack
#import yaml
# pip install logging
import logging

logger = ''
dns_map = ''

def main():
    global dns_map
    global logger

    logger = logging.getLogger()
    #fileHandler = logging.FileHandler('/var/log/dnsupdate.log')
    streamHandler = logging.StreamHandler(sys.stdout)
    #fileFormatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    streamFormatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    #fileHandler.setFormatter(fileFormatter)
    streamHandler.setFormatter(streamFormatter)
    #logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)
    logger.level = logging.INFO

    #work_dir = os.path.abspath(os.getcwd())
    #with open(f'{work_dir}/conf/param.yml') as f: #@TODO do we really need another file for static and code-documentary variables?
    param = {
            'AMQ_USERNAME': 'guest',
            'AMQ_PASSWORD': 'guest',
            'AMQ_HOSTNAME': 'localhost',
            'AMQ_PORT': '5672',
            'AMQ_EXCHANGE': 'cloudstack-events',
            'ACS_ENDPOINT': 'http://localhost:8080/client/api',
            'ACS_APIKEY': '',
            'ACS_SECRETKEY': '',
            'SQLITE_DB' : '/var/lib/acs-amq-dnsupdate.db',
            'DNS_MAP': '/etc/acs-amq-dnsupdate.json',
            }

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
        bstring = body.decode('ascii')
        blist = json.loads(bstring)
        logger.debug('AMQ Key: %r ,Body: %r' % (rklist, blist)) # raw message
        commandtype = ''
        if (
                (
                    rklist[0] == 'management-server' and
                    rklist[1] == 'AsyncJobEvent' and
                    rklist[2] == 'complete' and
                    rklist[3] == 'VirtualMachine'
                    ) or
                (
                    rklist[0] == 'management-server' and
                    rklist[1] == 'ActionEvent' and
                    rklist[2] == 'VM-UPDATE' and
                    rklist[3] == 'VirtualMachine'
                    )
                ):
                uuid = rklist[4]
                if ('instanceUuid' in blist and
                        'commandEventType' in blist and
                        'status' in blist and
                        blist['instanceUuid'] == uuid and
                        blist['status'] == 'SUCCEEDED'):
                    commandtype = blist['commandEventType']
                if ('entityuuid' in blist and
                        'event' in blist and
                        'status' in blist and
                        blist['entityuuid'] == uuid and
                        blist['status'] == 'Completed'):
                    commandtype = blist['event']

                # Pre check if UPDATE is really neccessary
                if (commandtype == 'VM.UPDATE'):
                    logger.debug('UPDATE VM WITH UUID: {uuid}')
                    oldhostname = ''
                    olddomain = ''
                    oldip4address = ''
                    oldip6address = ''
                    try:
                        con = sqlite3.connect(param['SQLITE_DB'])
                        cur = con.cursor()
                        cur.execute("SELECT vm_uuid,hostname,network_domain,network_uuid,a,aaaa FROM entries WHERE vm_uuid = '%s'" % uuid )
                        for row in cur:
                            oldhostname = row[1]
                            olddomain = row[2]
                            oldip4address = row[4]
                            oldip6address = row[5]
                        con.commit()
                        con.close()
                    except:
                        logger.warning(f'Unable to get current settings for for UUID: {uuid}')
                    newhostname = ''
                    newdomain = ''
                    newip4address = ''
                    newip6address = ''
                    vms = cs.listVirtualMachines(id=uuid, fetch_list=True)
                    if (len(vms) == 1):
                        vm = vms[0]
                        newhostname = vm['name']
                        if newhostname == '':
                            newhostname = uuid

                        newdomain = ''
                        newip4address = ''
                        newip6address = ''
                        for nic in vm['nic']:
                            if ('type' in nic and nic['type'] == 'Shared' and
                                    'isdefault' in nic and nic['isdefault'] == True and
                                    'networkid' in nic):
                                if ('ipaddress' in nic):
                                    newip4address = nic['ipaddress']
                                if ('ip6address' in nic):
                                    newip6address = nic['ip6address']
                                networks = cs.listNetworks(id=nic['networkid'], domainid=vm['domainid'], listall=True, fetch_list=True)
                                if (len(networks) == 1):
                                    network = networks[0]
                                    if ('networkdomain' in network):
                                        newdomain = network['networkdomain']
                    if (
                            (newhostname == oldhostname) and
                            (newdomain == olddomain) and
                            (newip4address == oldip4address) and
                            (newip6address == oldip6address)
                            ):
                        commandtype = '' # do not DESTROY and CREATE
                        logger.info(f'Skipped update for UUID: {uuid}. Nothing changed: {oldhostname} {olddomain} {oldip4address} {oldip6address}')
                    else:
                        logger.info(f'Update UUID: {uuid} old: {oldhostname} {olddomain} {oldip4address} {oldip6address}')
                        if ((newip4address != '' or newip6address != '') and newdomain != '' and validate_fqdn(newhostname + '.' + newdomain + '.') == True):
                            logger.info(f'Update UUID: {uuid} new: {newhostname} {newdomain} {newip4address} {newip6address}')
                        else:
                            commandtype = ''
                            logger.error(f'Skipped update for UUID: {uuid}. FQDN does not validate: {newhostname} {newdomain} {newip4address} {newip6address}')

                # DESTROY
                if (
                        (commandtype == 'VM.DESTROY') or
                        (commandtype == 'VM.UPDATE')
                        ):
                    logger.debug(f'DESTROY/UPDATE VM WITH UUID: {uuid}')
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
                        logger.error(f'Unable to remove records for UUID: {uuid}')

                # CREATE
                if (
                        (commandtype == 'VM.CREATE' and
                            'jobResult' in blist) or
                        (commandtype == 'VM.UPDATE')
                        ):
                    logger.debug(f'CREATE/UPDATE VM WITH UUID: {uuid}')
                    vms = cs.listVirtualMachines(id=uuid, fetch_list=True)
                    if (len(vms) == 1):
                        vm = vms[0]
                        hostname = vm['name']
                        if hostname == '':
                            hostname = uuid

                        domain = ''
                        ip4address = ''
                        ip6address = ''
                        for nic in vm['nic']:
                            if ('type' in nic and nic['type'] == 'Shared' and
                                    'isdefault' in nic and nic['isdefault'] == True and
                                    'networkid' in nic):
                                if ('ipaddress' in nic):
                                    ip4address = nic['ipaddress']
                                if ('ip6address' in nic):
                                    ip6address = nic['ip6address']
                                networks = cs.listNetworks(id=nic['networkid'], domainid=vm['domainid'], listall=True, fetch_list=True)
                                if (len(networks) == 1):
                                    network = networks[0]
                                    if ('networkdomain' in network):
                                        domain = network['networkdomain']
                            if ((ip4address != '' or ip6address != '') and domain != '' and validate_fqdn(hostname + '.' + domain + '.') == True):
                                try:
                                    logging.debug(f'Try to store record into db for UUID: {uuid}')
                                    con = sqlite3.connect(param['SQLITE_DB'])
                                    cur = con.cursor()
                                    cur.execute("INSERT INTO entries VALUES ('%s','%s','%s','%s','%s','%s')" %
                                            (uuid, hostname, domain, nic['networkid'], ip4address, ip6address))
                                    con.commit()
                                    con.close()
                                    try:
                                        logger.debug(f'Try to nsupdate for UUID: {uuid}')
                                        addrecords(uuid, hostname, domain, ip4address, ip6address)
                                    except:
                                        logger.error(f'Unable to nsupdate records for UUID: {uuid}')
                                except:
                                    logger.error(f'Unable to add records for UUID: {uuid}')
                            else:
                                logger.error(f'FQDN does not validate. Not adding records to UUID: {uuid}')

    logger.info('Listening for AMQ messages on amq://%s:%s/%s.' %
            (param['AMQ_HOSTNAME'], param['AMQ_PORT'], param['AMQ_EXCHANGE']))
    channel.basic_consume(callback,
            queue=queue_name,
            no_ack=True)

    channel.start_consuming()

def dnscfg():
    global dns_map
    global logger
    try:
        with open(dns_map) as json_file:
            cfg = json.load(json_file)
    except:
        logger.error(f'Unable to parse DNS Configuration from {dns_map}')
        cfg = {'tsigkeys': {}, 'zones': {} }
    return cfg

def validate_fqdn(dn):
    if dn.endswith('.'):
        dn = dn[:-1]
    if len(dn) < 1 or len(dn) > 253:
        return False
    ldh_re = re.compile('^[a-z0-9-]{2,63}$', re.IGNORECASE)
    return all(ldh_re.match(x) for x in dn.split('.'))

# get hardcoded /64 DNS PTR Zone from IPv6
def ptr6zone64(ip6rev):
    list = ip6rev.split('.')
    del list [0:16] # 16 elements equals /64
    return '.'.join(list)

def ptr6host64(ip6rev):
    list = ip6rev.split('.')
    del list [16:] # 16 elements equals /64
    return '.'.join(list)

# get hardcoded /16 DNS PTR Zone for IPv4
def ptr4zone16(ipvrev):
    list = ipvrev.split('.')
    del list[0:2] # 2 elements equals /16
    return '.'.join(list)

def ptr4host16(ipvrev):
    list = ipvrev.split('.')
    del list[2:] # 2 elements equals /16
    return '.'.join(list)

# Remove Nameserver Records
def removerecords(uuid='', hostname='', domain='', ip4address='', ip6address=''):
    global logger
    logger.info(f'Remove records for VM. uuid={uuid}, hostname={hostname}, domain={domain}, ip4address={ip4address}, ip6address={ip6address}')
    if ip6address != '':
        ip6 = ipaddress.ip_address(ip6address)
        ip6rev = ip6.reverse_pointer
        ptr6zone = ptr6zone64(ip6rev)
        ptr6host = ptr6host64(ip6rev)
        hasv6 = True
    else:
        ptr6zone = ''
        hasv6 = False
    if ip4address != '':
        ip4 = ipaddress.ip_address(ip4address)
        ip4rev = ip4.reverse_pointer
        ptr4zone = ptr4zone16(ip4rev)
        ptr4host = ptr4host16(ip4rev)
        hasv4 = True
    else:
        ptr4zone = ''
        hasv4 = False
    cfg = dnscfg()
    for zone in [ domain, ptr4zone, ptr6zone ]:
        if zone in cfg['zones']:
            for arhash in cfg['zones'][zone]:
                if ('tsigkey' in arhash) and (arhash['tsigkey'] in cfg['tsigkeys']):
                    tsighash = cfg['tsigkeys'][arhash['tsigkey']]
                    auth = { arhash['tsigkey']: tsighash['secret'] }
                    keyring = dns.tsigkeyring.from_text(auth)
                    if 'RR' in arhash:
                        for rrs in arhash['RR']:
                            rr = rrs.lower()
                            if rr == 'a' and domain != '' and hasv4 == True:
                                logger.info('Remove A record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                update = dns.update.Update(zone.lower(), keyring=keyring)
                                update.delete(hostname.lower(), 'a', ip4address)
                                response = dns.query.tcp(update, tsighash['host'])
                            elif rr == 'aaaa' and domain != '' and hasv6 == True:
                                logger.info('Remove AAAA record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                update = dns.update.Update(domain.lower(), keyring=keyring)
                                update.delete(hostname.lower(), 'aaaa', ip6address)
                                response = dns.query.tcp(update, tsighash['host'])
                            elif rr == 'ptr':
                                if hasv4 == True and zone == ptr4zone:
                                    logger.info('Remove PTR record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                    update = dns.update.Update(zone, keyring=keyring)
                                    update.delete(ptr4host, 'ptr', hostname.lower() + '.' + domain.lower() + '.')
                                    response = dns.query.tcp(update, tsighash['host'])
                                if hasv6 == True and zone == ptr6zone:
                                    logger.info('Remove PTR record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                    update = dns.update.Update(zone, keyring=keyring)
                                    update.delete(ptr6host, 'ptr', hostname.lower() + '.' + domain.lower() + '.')
                                    response = dns.query.tcp(update, tsighash['host'])

# Add Nameserver Records
def addrecords(uuid='', hostname='', domain='', ip4address='', ip6address=''):
    global logger
    logger.info(f'Add records for VM. uuid={uuid}, hostname={hostname}, domain={domain}, ip4address={ip4address}, ip6address={ip6address}')
    if ip6address != '':
        ip6 = ipaddress.ip_address(ip6address)
        ip6rev = ip6.reverse_pointer
        ptr6zone = ptr6zone64(ip6rev)
        ptr6host = ptr6host64(ip6rev)
        hasv6 = True
    else:
        ptr6zone = ''
        hasv6 = False
    if ip4address != '':
        ip4 = ipaddress.ip_address(ip4address)
        ip4rev = ip4.reverse_pointer
        ptr4zone = ptr4zone16(ip4rev)
        ptr4host = ptr4host16(ip4rev)
        hasv4 = True
    else:
        ptr4zone = ''
        hasv4 = False
    cfg = dnscfg()
    for zone in [ domain, ptr4zone, ptr6zone ]:
        if zone in cfg['zones']:
            for arhash in cfg['zones'][zone]:
                if ('tsigkey' in arhash) and (arhash['tsigkey'] in cfg['tsigkeys']):
                    tsighash = cfg['tsigkeys'][arhash['tsigkey']]
                    auth = { arhash['tsigkey']: tsighash['secret'] }
                    keyring = dns.tsigkeyring.from_text(auth)
                    if 'RR' in arhash:
                        for rrs in arhash['RR']:
                            rr = rrs.lower()
                            if rr == 'a' and domain != '' and hasv4 == True:
                                logger.info('Add A record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                update = dns.update.Update(zone.lower(), keyring=keyring)
                                update.replace(hostname.lower(), 300, 'a', ip4address)
                                response = dns.query.tcp(update, tsighash['host'])
                            elif rr == 'aaaa' and domain != '' and hasv6 == True:
                                logger.info('Add AAAA record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                update = dns.update.Update(domain.lower(), keyring=keyring)
                                update.replace(hostname.lower(), 300, 'aaaa', ip6address)
                                response = dns.query.tcp(update, tsighash['host'])
                            elif rr == 'ptr':
                                if hasv4 == True and zone == ptr4zone:
                                    logger.info('Add PTR record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                    update = dns.update.Update(zone, keyring=keyring)
                                    update.replace(ptr4host, 300, 'ptr', hostname.lower() + '.' + domain.lower() + '.')
                                    response = dns.query.tcp(update, tsighash['host'])
                                if hasv6 == True and zone == ptr6zone:
                                    logger.info('Add PTR record for %s in zone %s (tsigkey: %s)' % ( hostname.lower(), zone, arhash['tsigkey']))
                                    update = dns.update.Update(zone, keyring=keyring)
                                    update.replace(ptr6host, 300, 'ptr', hostname.lower() + '.' + domain.lower() + '.')
                                    response = dns.query.tcp(update, tsighash['host'])

#
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info('Exiting.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

