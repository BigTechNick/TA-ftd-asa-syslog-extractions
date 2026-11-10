# FTD and ASA Syslog Field Extractions Add-on for Cisco Secure Firewall

Splunk add-on `TA-ftd-asa-syslog-extractions`, version 1.0.0.

Search-time field extractions for Cisco Secure Firewall Threat Defense (FTD) and ASA syslog message IDs (sourcetype cisco:asa) that the Splunk Add-on for Cisco ASA and the Cisco Security Cloud app do not extract: VPN, IKEv2, WebVPN, UAUTH, GRE, NAT, routing, DNS, SIP and DCERPC inspection, FTD Linux and sudo messages. Install alongside either add-on. Not affiliated with Cisco.

## Layout

- `TA-ftd-asa-syslog-extractions/`: the app exactly as shipped to Splunkbase (unpacked from the release package)
- `tools/package.py`: builds the Splunkbase package and runs offline AppInspect-style checks
- `tests/`: tests with synthetic data (no Splunk or vendor account needed)

## Build

```
python3 tools/package.py TA-ftd-asa-syslog-extractions dist --vendor cisco
```

Good: `RESULT: OK`. Then AppInspect:

```
splunk-appinspect inspect dist/TA-ftd-asa-syslog-extractions-<version>.tgz --mode precert --included-tags cloud
```

## Tests

```
python3 tests/regex_test.py
```

## Packages

`packages/` will hold each version's package exactly as uploaded to Splunkbase, with `MD5SUMS`.
Not here yet: the 1.0.0 package and the app icons (`static/`); add them from the Splunkbase package.

## License

Apache-2.0. Independent project, not affiliated with or endorsed by Cisco.
