## Project

With names like **cloudstack-rabbitmq-dnsconsumer** or **acs-amq-dnsupdate** it aims for the badest project name on github.

### What is it useful for?

It's a simple but efficient **glue** between [Apache CloudStack](https://cloudstack.apache.org/) RabbitMQ and Nameservers with nsupdate/[RFC 2136](https://www.rfc-editor.org/info/rfc2136)-capabilities.

It's able of adding, modifying and removing A, AAAA and PTR ressource-records on behalf of creating, editing or destroying VirtualMachines in CloudStack.

### Schematics

```
---------------------
| apache cloudstack | <- VM creation, modification, removal
---------------------
         ||
     (rabbitMQ)
         \/
---------------------
| rabbitMQ exchange |
---------------------
         ||
     (rabbitMQ)
         \/
---------------------
| acs-amq-dnsupdate | <- (DNS TSIG and Zones YAML configuration)
---------------------\
         ||           \----------------------
     (RFC2136)        | SQLite stateful set |
         \/           -----------------------
---------------------
| authoritative \   |
|        nameserver |
---------------------
```

For this particular configuration example, we assume that the primary network is a [Cloudstack Shared Network](http://docs.cloudstack.apache.org/en/latest/adminguide/networking/advanced_zone_config.html#configuring-a-shared-guest-network). The network is configured as a dualstack VLAN with [IPv4 RFC 1918](https://www.rfc-editor.org/info/rfc1918)- and IPv6 public-addresses. It's DNS name shoud be identical to a (sub)domain delegated to an authoritative nameserver which needs to be accept Zone Updates via TSIG authentication. For this example, we publish IPv6 AAAA and IPv6 PTR to the public and private views of a split-horizon DNS (public./.internal), but to expose private IPv4 addresses (and their PTR counterpart) only to the private view.

See: [/etc/acs-amq-dnsupdate.json](conf/acs-amq-dnsupdate.json)

As an easy example, we install a RabbitMQ-Server locally. Apache CloudStack needs to be configured to use (http://docs.cloudstack.apache.org/en/latest/adminguide/events.html)[AMQP/RabbitMQ].
We're using the very same property values in our example:

See: [/etc/default/acs-amq-dnsupdate](conf/acs-amq-dnsupdate)

### How is it done?

**acs-amq-dnsupdate** registers to an RabbitMQ Exchange for cloudstack-events. If getting notified due to VM.CREATE, VM.MODIFY or VM.DESTROY messages, it subsequently verifies and completes the VM information via CloudStack API calls, and finally builds nsupdate queries based on a configuration matrix. A sqlite-db was added to get stateful sets.

See: [INSTALL.md](INSTALL.md)

