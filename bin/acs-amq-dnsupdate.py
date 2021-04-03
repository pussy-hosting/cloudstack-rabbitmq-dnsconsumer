#!/usr/bin/env python3
#
# /usr/local/bin/acs-dnsupdate.py
#
import pika
import json
import sys
import os
# pip install cs # https://github.com/exoscale/cs
from cs import CloudStack

def main():
    param = {
            'AMQ_USERNAME': 'guest',
            'AMQ_PASSWORD': 'guest',
            'AMQ_HOSTNAME': 'localhost',
            'AMQ_PORT': '5672',
            'AMQ_EXCHANGE': 'cloudstack-events',
            'ACS_ENDPOINT': 'http://localhost:8080/client/api',
            'ACS_APIKEY': '',
            'ACS_SECRETKEY': '',
            }

    for param_key, param_value in param.items():
        if param_key in os.environ:
            param[param_key] = os.getenv(param_key)

    cs = CloudStack(endpoint=ACS_ENDPOINT,
            key=ACS_APIKEY,
            secret=ACS_SECRETKEY)

    credentials = pika.PlainCredentials(AMQ_USERNAME, AMQ_PASSWORD)
    parameters = pika.ConnectionParameters(AMQ_HOSTNAME,
            int(AMQ_PORT),
            '/',
            credentials)

    connection = pika.BlockingConnection(parameters)

    channel = connection.channel()

    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue

    channel.queue_bind(exchange=AMQ_EXCHANGE,
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
                        removerecords(uuid)

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
                                addrecords(uuid, hostname, domain, ipaddress, ip6address)

    print('Listening for AMQ messages on amq://%s:%s/%s. To exit press CTRL+C' %
            ( AMQ_HOSTNAME, AMQ_PORT, AMQ_EXCHANGE ))
    channel.basic_consume(callback,
            queue=queue_name,
            no_ack=True)

    channel.start_consuming()

def validate_fqdn(dn):
    if dn.endswith('.'):
        dn = dn[:-1]
    if len(dn) < 1 or len(dn) > 253:
        return False
    ldh_re = re.compile('^[a-z0-9-]{2,63}$', re.IGNORECASE)
    return all(ldh_re.match(x) for x in dn.split('.'))

# Remove Nameserver Records
def removerecords(uuid=''):
    print('Remove records for VM. uuid=%s' % uuid)

# Add Nameserver Records
def addrecords(uuid='', hostname='', domain='', ipaddress='', ip6address=''):
    print('Add records for VM. uuid=%s, hostname=%s, domain=%s, ipaddress=%s, ip6address=%s' % (uuid, hostname, domain, ipaddress, ip6address))

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

