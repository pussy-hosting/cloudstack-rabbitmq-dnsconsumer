## Instalation

### Preflight / Preparation DNS

The file [/etc/acs-amq-update.json](../conf/acs-amq-update.json) contains the following setup as an example
  and a starting point for real configuration.

Assumed is a Primary Nameserver for the given Zones,
  configured with an Internal and an External View.

Assumed is also a Cloudstack Shared Network with
  following Definition:
    - IPv4: 10.100.0.0/16
    - IPv6: 2a00:12e8:202:1c64::/64
    - Domainname: v6-400.ber1.pussy-hosting.berlin

The desired setup provides IPv4 and IPv6 for the local networks,
  but hides the RFC1918 IPv4 from outside.

#### Zones:
- 100.10.in-addr.arpa

    as an RFC1918-Zone, only exists in Internal.
    Referenced by "cloudstack-internal" TSIGKEY
- 4.6.c.1.2.0.2.0.8.e.2.1.0.0.a.2.ip6.arpa

    exists in Internal *and* External View.
    Each referenced by the respective TSIGKEY.
- v6-400.ber1.pussy-hosting.berlin

    exists in Internal *and* External View.
    Referenced for A and AAAA by "cloudstack-internal",
      only for AAAA by "cloudstack-external".

#### BIND Configuration Snippets:
```
view "internal" {
        match-clients {
                key "cloudstack-internal";
                !key "cloudstack-external";
                local_nets;
        };
        allow-transfer {
                key internal-key;
        };
        allow-update { none; };
        zone "v6-400.ber1.pussy-hosting.berlin" IN {
                type master;
                file "v6-400.ber1.pussy-hosting.berlin.forward";
                also-notify {
                        85.158.0.163 key internal-key;
                        2a00:12e8:202:1c00::3 key internal-key;
                };
                allow-update {
                        key cloudstack-internal;
                };
        };
       zone "100.10.in-addr.arpa" {
                type master;
                file "100.10.in-addr.arpa.reverse";
                also-notify {
                        85.158.0.163 key internal-key;
                        2a00:12e8:202:1c00::3 key internal-key;
                };
                allow-update {
                        key cloudstack-internal;
                };
        };
       zone "4.6.c.1.2.0.2.0.8.e.2.1.0.0.a.2.ip6.arpa" {
                type master;
                file "4.6.c.1.2.0.2.0.8.e.2.1.0.0.a.2.ip6.arpa.reverse";
                also-notify {
                        85.158.0.163 key internal-key;
                        2a00:12e8:202:1c00::3 key internal-key;
                };
                allow-update {
                        key cloudstack-internal;
                };
        };
};
view "external" {
        match-clients {
                key "cloudstack-external";
                !key "cloudstack-internal";
                externals;
        };
        recursion no;
        allow-recursion { none; };
        allow-transfer {
                key external-key;
        };
        zone "v6-400.ber1.pussy-hosting.berlin" IN {
                type master;
                file "v6-400.ber1.pussy-hosting.berlin.forward_external";
                also-notify {
                        2a00:12e8:202:1c00::33 key external-key;
                };
                allow-update {
                        key cloudstack-external;
                };
        };
        zone "4.6.c.1.2.0.2.0.8.e.2.1.0.0.a.2.ip6.arpa" {
                type master;
                file "4.6.c.1.2.0.2.0.8.e.2.1.0.0.a.2.ip6.arpa.reverse_external";
                also-notify {
                        2a00:12e8:202:1c00::33 key external-key;
                };
                allow-update {
                        key cloudstack-external;
                };
        };
};
```

