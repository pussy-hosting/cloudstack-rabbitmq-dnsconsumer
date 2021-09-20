## Installation

### Prerequisites

- A running CloudStack setup, with at least one shared network, dns records should be
published for. Cloudstack-management should also be configured for publishing events
via AMQP.
See: [CloudStack AMQP Events](http://docs.cloudstack.apache.org/en/latest/adminguide/events.html#amqp-configuration)
The [doc/envvars.md](doc/envvars.md) covers the environment variables for configuring the CloudStack and rabbitmq bindings.

- A running rabbitmq (single or clustered). Consider to firewall this, also the initial
guest-user should be replaced for obvious reasons.

- An authoritative Nameserver (tested: bind9) for the DNS Zone(s) configured for the
shared network(s).

- The possiblity to add/remove the respective A, AAAA, optinally PTR records via nsupdate.
The [doc/acs-amq-dnsupdate.md](doc/acs-amq-dnsupdate.md) gives an Example for a working setup.

### Daemon setup

That's the easist step. The daemon only glues messages and nsupdate together.
See also [doc/schema.md](doc/schema.md).

Python 3 is a requirement. Tested under Ubuntu 20.04 LTS
```
apt install python3-dnspython
# pip3 install pip # unsure, if necessary
pip install cs
pip install logging
```

```
git clone https://github.com/pussy-hosting/cloudstack-rabbitmq-dnsconsumer.git
cd cloudstack-rabbitmq-dnsconsumer
install -m 0755 -u root -g root bin/acs-amq-dnsupdate.py /usr/local/bin
install -m 0644 -u root -g root systemd/acs-amq-dnsupdate.service /etc/systemd/system
install -m 0640 -u root -g root conf/acs-amq-dnsupdate /etc/default
install -m 0640 -u root -g root conf/acs-amq-dnsupdate.json /etc
vi /etc/default/acs-amq-dnsupdate
vi /etc/acs-amq-dnsupdate.json
systemctl daemon-reload
systemctl enable --now acs-amq-dnsupdate
```

