## Installation

### Preflight / Preparation CloudStack

The file [/etc/default/acs-amq-dnsupdate](../conf/acs-amq-dnsupdate) contains the commented default
values for the necessary environment variables.

See: [CloudStack AMQP Events](http://docs.cloudstack.apache.org/en/latest/adminguide/events.html#amqp-configuration)

#### Considerations

- Do *not* use the default guest/guest credentials for the default rabbitmq user. Create a new one and remove the guest-user.
- Consider creating a "*read-only but read everything*" Cloudstack Role with an api-user for ACS_APIKEY / ACS_SECRETKEY

