## Message Flow

```
cloudstack-management   ->  RabbitMQ
                            exchange: cloudstack-events
                              ^             |
                            1.|register  2. |message
                              |queue        |management-server.AsyncJobEvent.complete.\
                              |             |             VirtualMachine.$uuid.VM.[DESTROY|CREATE|MODIFY]
                              |             |
                       .----acs-amq-dnsupdate.py
                       |     |     |    |   |
                       |     |     |    | 3.`<-------> cloudstack API callback (get VM $uuid details)
                       |     |     | ADD|
                       |     |     |  4.|register VM hints
                       |     |     |    `---> compare against MODIFY/add in sqlite
                       |     |  ADD|
                       |     |   5.|register A + AAAA + PTR
                       |     |     `---> nsupdate add A
                       |     |     `---> nsupdate add AAA
                       |     |     `---> nsupdate add PTR
                       |  DEL|
                       |   4.|get VM hints
                       |     `<----- sqlite
                    DEL|
                     5.|remove A, AAA, PTR and VM hints
                       `----> nsupdate delete A
                       `----> nsupdate delete AAA
                       `----> nsupdate delete PTR
                       `----> remove in sqlite
```

See also:
[http://docs.cloudstack.apache.org/en/latest/adminguide/events.html#amqp-configuration]

