## Project

With names like **cloudstack-rabbitmq-dnsconsumer** or **acs-amq-dnsupdate** it aims for the badest project name on github.

### What it's useful for?

It's a simple but efficient **glue** between [Apache CloudStack](https://cloudstack.apache.org/) RabbitMQ and Nameservers with nsupdate/[RFC 2136](https://www.rfc-editor.org/info/rfc2136)-capabilities.

### How is it done?

**acs-amq-dnsupdate** registers to an RabbitMQ Exchange for cloudstack-events. If getting notified due to VM.CREATE, VM.MODIFY or VM.DESTROY messages, it subsequently verifies and completes the VM information via CloudStack API calls, and finally builds nsupdate queries based on a configuration matrix. A sqlite-db was added to get stateful sets.

See: [INSTAll.md](INSTALL.md)
