## Message Flow

```
cloudstack-management   ->  rabbitmq (see [1])
                            exchange: cloudstack-events
                              ^             |
                            1.|register  2. |message
                              |queue        |management-server.AsyncJobEvent.complete.\
                                            |             VirtualMachine.$uuid.VM.[DESTROY|CREATE]
                              |             |
                       .----acs-amq-dnsupdate.py
                       |     |     |    |   |
                       |     |     |    | 3.`<-------> cloudstack API callback (get VM $uuid details)
                       |     |     | ADD|
                       |     |     |  4.|register VM hints in $uuid.uuid-domain-zone
                       |     |     |    `---> nsupdate add TXT
                       |     |  ADD|
                       |     |   5.|register A + AAAA + PTR
                       |     |     `---> nsupdate add A
                       |     |     `---> nsupdate add AAA
                       |     |     `---> nsupdate add PTR
                       |  DEL|
                       |   4.|get VM hints from uuid.uuid.domain-zone
                       |     `<----- nslookup
                    DEL|
                     5.|remove A, AAA, PTR and VM hints
                       `----> nsupdate delete A
                       `----> nsupdate delete AAA
                       `----> nsupdate delete PTR
                       `----> nsupdate delete TXT ($uuid.uuid-domain-zone)
```

[1]: http://docs.cloudstack.apache.org/en/latest/adminguide/events.html#amqp-configuration]
