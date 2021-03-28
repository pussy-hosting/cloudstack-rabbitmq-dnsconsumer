#!/usr/bin/env python3
import pika
import json
import sys
import os
# pip install cs # https://github.com/exoscale/cs
from cs import CloudStack

def main():
    amq_user     = 'cloudstack'
    amq_pass     = 'queuediekuh'
    amq_host     = 'localhost'
    amq_exchange = 'cloudstack-events'

    cs_endpoint  = 'http://localhost:8080/client/api'
    cs_apikey    = 'kM43Ngg64xky5z2KebBehQqhy6I2huZL0B1DBDh84L_Ii9ibWG0ib3YVO5Rzg7MEbayOghiZk0QglRbmernW2g'
    cs_secretkey = 'RcfD7erAy-0yaSMM39A9H6PPyy958Sdc7tDAVKDmteFSw3Iw2qyJ6aoNUC80KrUAP2OXhi0twAd9sp7hXyMtDA'

    cs = CloudStack(endpoint=cs_endpoint,
            key=cs_apikey,
            secret=cs_secretkey)

    credentials = pika.PlainCredentials(amq_user, amq_pass)
    parameters = pika.ConnectionParameters(amq_host,
            5672,
            '/',
            credentials)

    connection = pika.BlockingConnection(parameters)

    channel = connection.channel()

    result = channel.queue_declare(exclusive=True)
    queue_name = result.method.queue

    channel.queue_bind(exchange=amq_exchange,
            routing_key='#',
            queue=queue_name)

    print(' [*] Waiting for logs. To exit press CTRL+C')

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
                            addrecords(uuid, hostname, domain, ipaddress, ip6address) 

    channel.basic_consume(callback,
            queue=queue_name,
            no_ack=True)

    channel.start_consuming()

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
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)

