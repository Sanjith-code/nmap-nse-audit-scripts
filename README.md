# Nmap NSE Audit Scripts: SNMP and NTP

Coursework lab project containing a reference SNMP information check, two SNMP
enhancements, a reference-style NTP Mode 7 monlist check, and two NTP
enhancements. Use only on systems you own or are authorized to assess.

## Scripts

| Service | Script | Purpose |
| --- | --- | --- |
| SNMP | [`snmp-sysdescr-reference.nse`](scripts/snmp-sysdescr-reference.nse) | Reference check that retrieves the standard system description and uptime. |
| SNMP | [`snmp-public-check-option1.nse`](scripts/snmp-public-check-option1.nse) | Checks whether the default community `public` can read `sysDescr.0`; reports potential exposure or an inconclusive result. |
| SNMP | [`snmp-public-check-option2.nse`](scripts/snmp-public-check-option2.nse) | Checks whether `public` can read `sysName.0` and `sysDescr.0`. |
| NTP | [`ntp-custom.nse`](scripts/ntp-custom.nse) | Reference-style Mode 7 monlist response check. A response needs validation; silence is inconclusive. |
| NTP | [`ntp-monlist-enhanced1.nse`](scripts/ntp-monlist-enhanced1.nse) | Validates the Mode 7 response and distinguishes a non-matching reply from no reply. Loopback only. |
| NTP | [`ntp-monlist-enhanced2.nse`](scripts/ntp-monlist-enhanced2.nse) | Reports a bounded one-datagram size ratio; this is not a full amplification measurement. Loopback only. |

## Local Ubuntu/WSL lab

Install Nmap and the services used in the localhost demonstrations:

```bash
sudo apt update
sudo apt install -y nmap snmpd snmp chrony
nmap --version
```

For the NTP test, configure Chrony in `/etc/chrony/chrony.conf` to listen on
loopback only:

```conf
allow 127.0.0.1
bindaddress 127.0.0.1
```

Restart Chrony and verify its UDP listener:

```bash
sudo service chrony restart
sudo ss -lunp | grep ':123'
```

The NTP scan used for the supplied screenshot was run from the repository root:

```bash
sudo env NMAPDIR="$PWD" nmap -sU -Pn -p 123 \
  --script ./scripts/ntp-custom.nse,./scripts/ntp-monlist-enhanced1.nse,./scripts/ntp-monlist-enhanced2.nse \
  127.0.0.1
```

Run the SNMP scripts only against a local SNMP lab you control:

```bash
sudo service snmpd start
sudo nmap -n -Pn -sU -p 161 --reason --script ./scripts/snmp-sysdescr-reference.nse 127.0.0.1
sudo nmap -n -Pn -sU -p 161 --reason --script ./scripts/snmp-public-check-option1.nse 127.0.0.1
sudo nmap -n -Pn -sU -p 161 --reason --script ./scripts/snmp-public-check-option2.nse 127.0.0.1
```

Do not enable legacy Mode 7 or expose UDP/123 to a network for a positive demo.
The [NTP `ntpdc` manual](https://www.ntp.org/documentation/4.2.8-series/ntpdc/)
and [NTP configuration manual](https://www.ntp.org/documentation/4.2.8-series/ntp.conf/)
describe the legacy context.

## Interpreting results

- An SNMP value returned with community `public` is evidence that the queried
  object is readable with that default community. It does not establish access
  to every object or prove write access.
- A matching NTP Mode 7 reply is evidence of a legacy response. Review the
  server version and configuration before concluding whether CVE-2013-5211
  applies.
- UDP/123 `closed`, `open|filtered`, silence, or timeout is **inconclusive**,
  not proof that the service is secure. Filtering, bindings, disabled Mode 7,
  query restrictions, version differences, and packet loss can suppress a reply.
- Enhancement 2 measures only the first UDP datagram; its ratio is a limited
  local indicator, not a complete amplification factor.

## Blog material and screenshots

- [`blog/blog1_snmp_enhancement.html`](blog/blog1_snmp_enhancement.html) is the
  SNMP post with terminal screenshots embedded.
- [`blog/blog2_nmap_lab_steps.html`](blog/blog2_nmap_lab_steps.html) is the
  NTP-focused walkthrough with the authentic localhost scan screenshot embedded.
- SNMP captures are in [`screenshots/snmp/`](screenshots/snmp/).
- The NTP capture is [`screenshots/ntp/04-loopback-combined-output.png`](screenshots/ntp/04-loopback-combined-output.png).

## Validation note

The included NTP terminal capture was supplied after an actual run with Nmap
7.98 against Chrony listening on `127.0.0.1:123`. Nmap reported UDP/123 open;
all three custom scripts reported no monlist reply and an inconclusive result.
This does not prove that the host is secure or demonstrate a vulnerable server.
