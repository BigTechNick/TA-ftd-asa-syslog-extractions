# FTD and ASA Syslog Field Extractions Add-on for Cisco Secure Firewall

Version 1.1.0. App ID (folder name): `TA-ftd-asa-syslog-extractions`.

Search-time field extractions for Cisco Secure Firewall Threat Defense (FTD)
and ASA syslog message IDs, sourcetype `cisco:asa`, that neither the Splunk
Add-on for Cisco ASA nor the Cisco Security Cloud app extracts. Install it
alongside either of them: it adds fields and leaves their parsing as it is.

Since 1.1.0 it also fixes CIM mappings of the **Cisco Security Cloud** app's FTD
syslog (`cisco:ftd:syslog`), eStreamer (`cisco:sfw:estreamer`) and ASA session
data, and switches off six of that app's event types that put most firewall
traffic into the wrong data models. See [CIM fixes for the Cisco Security Cloud
app](#cim-fixes-for-the-cisco-security-cloud-app). Without the Cisco Security
Cloud app those settings do nothing.

> Independent project, not affiliated with or endorsed by Cisco. Cisco and
> Cisco Secure Firewall are trademarks of Cisco Systems, Inc. See NOTICE.

## Where to install

| Splunk instance | Install? |
|---|---|
| Search heads (including Splunk Cloud and Enterprise Security) | Yes |
| Heavy forwarders, indexers | No (search-time settings only) |

Requirements:

* FTD or ASA syslog indexed with sourcetype `cisco:asa`, the sourcetype the
  Splunk Add-on for Cisco ASA and Cisco Security Cloud use for these messages
  (Cisco Security Cloud puts only FTD's 430xxx events in `cisco:ftd:syslog`).
* The Splunk Add-on for Cisco ASA or Cisco Security Cloud on the same search
  heads, for the rest of the parsing and the CIM mappings.
* For the CIM fixes: the Cisco Security Cloud app (tested with 4.1.3) on the same
  search heads.

Nothing to configure. The extractions are exported to all apps.

## What it adds

| Message ID | Event | Fields |
|---|---|---|
| 104001 / 104002 / 104004 | Failover: switching to active / standby / OK | failover_unit, failover_state, reason |
| 105003 / 105004 | Failover interface monitoring waiting / normal | failover_unit, interface, monitor_status |
| 105006 / 105007 | Failover link status up / down | failover_unit, link_status, interface |
| 106010 | Deny inbound protocol | vendor_action, direction, transport / protocol_number, src_*, dest_* |
| 106021 | Reverse-path-check deny | vendor_action, transport, src_ip, dest_ip, src_interface |
| 106102 | VPN filter ACL hit | rule, vendor_action, transport, user, src_*, dest_*, hit_count |
| 109201 / 109207 / 109210 | UAUTH entry added, updated, removed | user, assigned_ip, session_id, uauth_result |
| 199016 / 199017 / 199018 | FTD Linux and chassis (FXOS) syslog; sudo; chassis audit | process_name, process_id; sudo: src_user, user, tty, pwd, command; FPRM: fprm_severity, fprm_event; audit: fprm_audit_type, fprm_audit_user, fprm_audit_action, fprm_audit_cause, fprm_audit_id, and user, src_ip, command, session_id, reason for sign-ins, commands and session ends |
| 199022 / 199024 | Configuration backup started / finished | backup_status, backup_time, backup_target |
| 121003 | Chassis telemetry request | telemetry_msg_id, telemetry_message, sse_connector_status, telemetry_blade_config, telemetry_result |
| 202010 | PAT / NAT pool exhausted | reason, nat_pool, nat_pool_ip, nat_port_range, transport, src_*, dest_* |
| 209003 / 209005 | Fragment limits exceeded | reason, fragment_limit, src_ip, dest_ip, transport, fragment_id |
| 209006 | Fragment dropped, queue threshold exceeded | vendor_action, transport, src_ip, src_port, dest_ip, dest_port, src_interface |
| 210005 | LU allocate failure | lu_object, transport, src_*, dest_* |
| 210007 | LU allocate xlate failure | nat_type, transport, src_*, dest_*, src/dest_translated_ip and _port |
| 210022 | LU missed updates | lu_missed_updates |
| 302017 / 302018 | GRE connection built / torn down | vendor_action, direction, transport, connection_id, src_*, dest_*, gre_call_id, duration, bytes |
| 302037 / 302038 | IP-in-IP connection built / torn down | vendor_action, direction, transport, connection_id, src_*, dest_*, duration, bytes |
| 305006 | NAT translation creation failed | nat_type, transport, src_*, dest_*, icmp_type, icmp_code |
| 313008 | IPv6-ICMP denied | vendor_action, transport, icmp_type, icmp_code, src_ip, src_interface |
| 317077 / 317078 | Route added / deleted | route_action, route_type, route_network, route_mask, route_next_hop, route_distance, route_metric, route_interface |
| 411001 / 411002 | Interface line protocol up / down | interface, interface_status |
| 410001 | DNS packet dropped | vendor_action, transport, dns_message_type, src_*, dest_*, reason |
| 447001 | ASP punt queue full | queue_name, queue_length, queue_limit |
| 508001 | DCERPC unknown version | reason, dcerpc_version, src_*, dest_* |
| 508002 | DCERPC low endpoint port | dcerpc_endpoint_port, src_*, dest_* |
| 607002 | SIP inspection | sip_action_class, sip_action, sip_type, sip_code, src_*, dest_*, sip_detail |
| 713050 | IPsec connection terminated | group, src_ip (peer), reason, remote_proxy, local_proxy |
| 713257 | IKE phase 1 attribute mismatch | ike_phase, reason, ike_received, ike_configured |
| 713259 | IKE session torn down | group, src_ip (peer), reason |
| 713904 | IKE packet dropped | group, src_ip (peer), ike_message |
| 716164 | SAML relay state integrity failure | reason, src_ip (client) |
| 717004 | PKCS #12 export failed | trustpoint |
| 720027 / 720028 / 720032 / 720037 / 720039 / 720040 | VPN failover status and progression | ha_component, failover_unit, ha_my_state, ha_peer_state, ha_event, ha_op, ha_id, ha_seq, ha_group |
| 721002 / 721003 | WebVPN failover status and progression | ha_component, failover_unit, ha_event, ha_my_state, ha_peer_state |
| 721016 / 721018 | WebVPN session created / deleted | user, src_ip, session_action, webvpn_role |
| 722013 | AnyConnect client (SVC) message | group, user, src_ip, svc_message_id, svc_severity, svc_message |
| 722035 | AnyConnect large packet | group, user, src_ip, packet_size, packet_threshold |
| 750xxx / 751xxx | IKEv2 (except 751025, 751026) | src_ip / src_port (remote peer), dest_ip / dest_port (firewall), ike_username, ike_message, reason |
| 752xxx | Tunnel manager | crypto_map, crypto_map_seq |

`src_*` / `dest_*` = `_interface`, `_ip` and `_port`, where the message has them.

## CIM fixes for the Cisco Security Cloud app

Tested with Cisco Security Cloud 4.1.3 and Splunk Common Information Model 8.8.0.

| Data | Problem in Cisco Security Cloud | Fix |
|---|---|---|
| `cisco:ftd:syslog` action (Network_Traffic, Intrusion_Detection) | Raw FTD values: Allow, Block, Block with reset, Trust, Fastpath, InlineResult Alert / Block | Lookup to `allowed` / `blocked` |
| `cisco:ftd:syslog` src (Network_Traffic, Intrusion_Detection, Alerts) | Aliased from ReferencedHost (the HTTP Host / TLS SNI name, i.e. the destination); empty on most events | Initiator IP (`SrcIP`, `InitiatorIP`) |
| `cisco:ftd:syslog` signature, severity (Intrusion_Detection, Alerts) | Not set; severity is aliased from EventPriority, which syslog does not carry | signature from `Message`; severity from `Priority` (1 high, 2 medium, 3 low, 4+ informational) |
| `cisco:ftd:syslog` 430002 / 430003 | Every connection tagged `certificate` and `ssl` (Certificates), every connection end tagged `session` (Network_Sessions) | Event types switched off; connections stay in Network_Traffic |
| `cisco:ftd:syslog` 430004 | File events tagged `endpoint` `filesystem` (Endpoint) | Event type switched off |
| `cisco:sfw:estreamer` file events | Tagged `endpoint` `filesystem` (Endpoint); tagged `malware` `attack` `alert` when SHA_Disposition is Malware **or Unknown** (most files) | Event types switched off; `ftdx_estreamer_malware` tags only Malware verdicts and FileMalwareEvent |
| `cisco:sfw:estreamer` action | Fastpath and other access control actions left raw | Same action lookup |
| `cisco:asa` Network_Sessions | 725003 / 725007 (SSL session resume / terminated, no user) tagged as sessions | `ftdx_asa_network_sessions`: Cisco's list without those two |

Event types switched off (`disabled = 1`): `cisco_syslog_ConnectionEvent_begin_connect`,
`cisco_syslog_ConnectionEvent_end_connect`, `cisco_syslog_FileEvent`,
`cisco_estreamer_FileEvent`, `cisco_estreamer_FileEvent_malware`,
`cisco_asa_network_sessions`.

Why it works this way: Splunk ranks an app's `default` settings by folder name, and
`CiscoSecurityCloud` outranks `TA-ftd-asa-syslog-extractions`, so this add-on cannot change a
setting Cisco sets. Every fix therefore uses a setting Cisco does not set: `disabled` on its
event types, and calculated fields and a lookup, which Splunk applies after Cisco's field
aliases and calculated fields.

Side effects to know about:

* Cisco's own `Cisco_Security` data model still finds these events by `EventType`; only a
  label in it that names `cisco_asa_network_sessions` no longer applies to the sessions.
* An action value the lookup does not list becomes empty (CIM `unknown`); the vendor value is
  still in `AccessControlRuleAction`, `InlineResult` or `AC_RuleAction`.
* `Monitor` maps to `allowed` (the rule logs and lets the connection continue).

After upgrading Cisco Security Cloud, check that the event types are still switched off and that
nothing else sets the fields:

```
splunk btool eventtypes list --debug | grep -B1 "disabled = 1"
splunk btool props list cisco:ftd:syslog --debug | grep -E "EVAL-(src|severity)|LOOKUP-ftdx|FIELDALIAS-ftdx"
```

## Not covered on purpose

* An add-on already extracts them: 111008, 113009, 302010, 711004, 713049, 713120,
  733100, 734001, 737003, 737006, 737016, 737026, 737034, 746014, 746015, 746016,
  751025, 751026, 771002.
* Nothing worth extracting: 752011, 880002.

## Design notes

* Each extraction is anchored on its own message ID (`%FTD-<level>-<id>:` or
  `%ASA-<level>-<id>:`), so it runs only on that message.
* Class names are unique (`EXTRACT-ftdx_<id>`), so they add to other apps'
  extractions and never replace them.
* `user` is not set when FTD logs `'<unknown>'` (106102). IKEv2 usernames go to
  `ike_username`, because FTD often logs the peer address or `Unknown` there.
* 199017 sets `process_name` on every message, and the sudo fields on sudo
  messages.

## Check after installing

Extractions:

```
index=<your firewall index> sourcetype="cisco:asa" earliest=-1h
| rex "%(?:FTD|ASA)-\d-(?<mid>\d{6})"
| search mid IN (106010, 106021, 106102, 202010, 210007, 302017, 302037, 305006, 713050, 722013)
| stats count dc(src_ip) dc(dest_ip) by mid
```

CIM fixes (run from the app the data model acceleration uses, Splunk_SA_CIM, or any app):

```
index=<your firewall index> sourcetype="cisco:ftd:syslog" earliest=-15m
| stats count by action
```

```
index=<your firewall index> sourcetype="cisco:ftd:syslog" earliest=-15m
| eval src_is_ip=if(match(src, "^\d+\.\d+\.\d+\.\d+$"), "yes", "no")
| stats count by src_is_ip
```

```
| tstats count from datamodel=Certificates where sourcetype="cisco:ftd:syslog" earliest=-1h
```

Data model summaries built before the upgrade keep the old tags until they are rebuilt or age
out, so check `tstats` over a window that starts after the upgrade.

## Release notes

### 1.1.0

* CIM fixes for the Cisco Security Cloud app's `cisco:ftd:syslog`, `cisco:sfw:estreamer`
  and `cisco:asa` session data (action, src, signature, severity; six over-broad event types
  switched off, two narrower replacements).
* No change to the 1.0.0 extractions.

### 1.0.0

* First release.

## Support

Community-supported, best effort, through Splunkbase. Licensed under Apache 2.0.
