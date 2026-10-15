# Nmap NSE Audit Scripts: SNMP and NTP

Coursework lab project with a reference SNMP information check, two SNMP
enhancements, an NTP Mode 7 monlist reference check, and two NTP enhancements.
The scripts are intended for authorized local testing and clearer audit output.

## Scripts

| Service | Script | Purpose |
| --- | --- | --- |
| SNMP | [`snmp-sysdescr-reference.nse`](scripts/snmp-sysdescr-reference.nse) | Reference check that retrieves the standard system description and uptime. Based on the Nmap script by Thomas Buchanan. |
| SNMP | [`snmp-public-check-option1.nse`](scripts/snmp-public-check-option1.nse) | Checks whether the default community `public` can read `sysDescr.0`; reports potential information exposure or an inconclusive result. |
| SNMP | [`snmp-public-check-option2.nse`](scripts/snmp-public-check-option2.nse) | Checks whether `public` can read `sysName.0` and `sysDescr.0`, then reports only returned values. |
| NTP | [`ntp-custom.nse`](scripts/ntp-custom.nse) | Reference-style Mode 7 monlist response check. A response needs validation; silence is inconclusive. |
| NTP | [`ntp-monlist-enhanced1.nse`](scripts/ntp-monlist-enhanced1.nse) | Validates the Mode 7 response bit, mode, implementation, opcode, and minimum header length. Runs against loopback only. |
| NTP | [`ntp-monlist-enhanced2.nse`](scripts/ntp-monlist-enhanced2.nse) | Adds a byte count and a single-datagram response/request ratio; it is not a full amplification test. Runs against loopback only. |

## Run in an Ubuntu/WSL lab

Install Nmap and, if needed, local SNMP and NTP services:

```bash
sudo apt update
sudo apt install -y nmap snmpd snmp chrony
nmap --version
```

Start and inspect the local services only if you need them for your lab:

```bash
sudo systemctl start snmpd
sudo systemctl status snmpd
sudo systemctl start chrony
sudo systemctl status chrony
```

From the repository root, run one SNMP script at a time against loopback:

```bash
sudo nmap -n -Pn -sU -p 161 --reason --script ./scripts/snmp-sysdescr-reference.nse 127.0.0.1
sudo nmap -n -Pn -sU -p 161 --reason --script ./scripts/snmp-public-check-option1.nse 127.0.0.1
sudo nmap -n -Pn -sU -p 161 --reason --script ./scripts/snmp-public-check-option2.nse 127.0.0.1
```

Run the NTP checks against loopback only:

```bash
sudo nmap -n -Pn -sU -p 123 --reason --script ./scripts/ntp-custom.nse 127.0.0.1
sudo nmap -n -Pn -sU -p 123 --reason --script ./scripts/ntp-monlist-enhanced1.nse 127.0.0.1
sudo nmap -n -Pn -sU -p 123 --reason --script ./scripts/ntp-monlist-enhanced2.nse 127.0.0.1
```

Do not change the target to a public server or a system you do not administer.
Do not enable legacy Mode 7 or expose UDP/123 to the network for a positive
demo. NTP Mode 7 is legacy functionality; current NTP configuration docs
describe it as disabled by default and deprecated. See the [NTP `ntpdc` manual](https://www.ntp.org/documentation/4.2.8-series/ntpdc/)
and [NTP configuration manual](https://www.ntp.org/documentation/4.2.8-series/ntp.conf/).

## Interpreting results

- An SNMP value returned with community `public` is evidence that the queried
  object is readable with that default community. It does not establish access
  to every object or prove write access.
- A matching NTP Mode 7 reply is evidence of a legacy response. Review the
  server version and configuration before concluding whether CVE-2013-5211
  applies.
- UDP/123 `closed`, `open|filtered`, silence, or timeout is **inconclusive**,
  not proof that the service is secure. Filtering, bindings, disabled Mode 7,
  query restrictions, version differences, and packet loss can all suppress a
  reply.
- Enhancement 2 measures only the first UDP datagram; its ratio is a limited
  local indicator, not a complete amplification factor.

## Blog material and screenshots

- [`blog/blog1_snmp_enhancement.html`](blog/blog1_snmp_enhancement.html) is the
  SNMP post with the real terminal screenshots embedded.
- [`blog/blog2_nmap_lab_steps.html`](blog/blog2_nmap_lab_steps.html) contains
  the lab walkthrough. It still has a YouTube-link placeholder and is a draft.
- The original PNG captures are in [`screenshots/snmp/`](screenshots/snmp/).

## Validation note

The screenshots are supplied terminal captures. Earlier NTP script versions
were loaded by Nmap 7.98 and exercised against a temporary loopback mock; that
was not a real NTP service. The reference file and package were subsequently
updated, so the current combined set has not been re-executed in Nmap. No
screenshots or scan results were generated for this repository build.

