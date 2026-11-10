#!/usr/bin/env python3
"""
regex_test.py - every EXTRACT in default/props.conf against sample FTD syslog lines (made-up hosts,
documentation IP ranges): each sample must match its extraction with the expected fields, and no
extraction may match a message ID it is not meant for.
Splunk's PCRE named groups (?<name>...) are converted to Python's (?P<name>...).
"""
import os
import re
import sys

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "TA-ftd-asa-syslog-extractions")
P = "<164>Nov 04 2026 15:01:02 fw-example-01 : "

SAMPLES = [
    ("106010", P + "%FTD-3-106010: Deny inbound protocol 103 src inside:192.0.2.10 dst identity:224.0.0.13",
     dict(vendor_action="Deny", direction="inbound", protocol_number="103", src_interface="inside",
          src_ip="192.0.2.10", dest_interface="identity", dest_ip="224.0.0.13")),
    ("106010", P + "%ASA-3-106010: Deny inbound protocol 47 src outside:203.0.113.5 dst inside:192.0.2.11",
     dict(vendor_action="Deny", protocol_number="47", src_ip="203.0.113.5", dest_ip="192.0.2.11")),
    ("106010", P + "%FTD-3-106010: Deny inbound tcp src outside:203.0.113.7/51515 dst inside:192.0.2.20/22",
     dict(transport="tcp", src_ip="203.0.113.7", src_port="51515", dest_ip="192.0.2.20", dest_port="22")),
    ("106021", P + "%FTD-1-106021: Deny ICMP reverse path check from 198.51.100.4 to 192.0.2.30 on interface vpn-1",
     dict(vendor_action="Deny", transport="ICMP", src_ip="198.51.100.4", dest_ip="192.0.2.30", src_interface="vpn-1")),
    ("106102", P + "%FTD-6-106102: access-list vpn-filter permitted tcp for user 'jdoe' outside/198.51.100.9(1234) "
     "-> inside/192.0.2.40(587) hit-cnt 1 first hit [0x1, 0x0]",
     dict(rule="vpn-filter", vendor_action="permitted", transport="tcp", user="jdoe", src_ip="198.51.100.9",
          src_port="1234", dest_ip="192.0.2.40", dest_port="587", hit_count="1")),
    ("106102", P + "%FTD-6-106102: access-list vpn-filter denied udp for user '<unknown>' outside/198.51.100.9(53) "
     "-> inside/192.0.2.40(53) hit-cnt 3",
     dict(vendor_action="denied", user=None, hit_count="3")),
    ("1092xx", P + "%FTD-6-109201: UAUTH: Session=0x1a2b, User=jdoe, Assigned IP=192.0.2.50, Succeeded adding entry.",
     dict(session_id="0x1a2b", user="jdoe", assigned_ip="192.0.2.50", uauth_result="Succeeded adding entry")),
    ("19901x_process", P + "%FTD-7-199017: sshd[4321]: Accepted publickey for admin from 192.0.2.60 port 50000 ssh2",
     dict(process_name="sshd", process_id="4321")),
    ("199017_sudo", P + "%FTD-7-199017: sudo: root : TTY=console ; PWD=/ ; USER=root ; COMMAND=/usr/local/sf/bin/pmtool status#012",
     dict(src_user="root", tty="console", pwd="/", user="root", command="/usr/local/sf/bin/pmtool status")),
    ("210005", P + "%FTD-3-210005: LU allocate connection failed for TCP connection from inside:192.0.2.70/51392 "
     "to outside:203.0.113.8/443",
     dict(lu_object="connection", transport="TCP", src_ip="192.0.2.70", src_port="51392", dest_ip="203.0.113.8",
          dest_port="443")),
    ("302017_inbound", P + "%FTD-6-302017: Built inbound GRE connection 12345 from outside:203.0.113.9 (203.0.113.9) "
     "to inside:192.0.2.80/0 (192.0.2.80/0)",
     dict(vendor_action="Built", direction="inbound", transport="GRE", connection_id="12345", src_ip="203.0.113.9",
          dest_ip="192.0.2.80", gre_call_id="0")),
    ("302017_outbound", P + "%FTD-6-302017: Built outbound GRE connection 12346 from outside:203.0.113.9 (203.0.113.9) "
     "to inside:192.0.2.80/7 (192.0.2.80/7)",
     dict(direction="outbound", dest_ip="203.0.113.9", src_ip="192.0.2.80", gre_call_id="7")),
    ("302018", P + "%FTD-6-302018: Teardown GRE connection 12345 from outside:203.0.113.9 to inside:192.0.2.80/0 "
     "duration 0:02:01 bytes 0",
     dict(vendor_action="Teardown", connection_id="12345", duration="0:02:01", bytes="0")),
    ("305006", P + "%FTD-3-305006: regular translation creation failed for icmp src guest:192.0.2.90 dst "
     "outside:203.0.113.10 (type 3, code 3)",
     dict(nat_type="regular", transport="icmp", src_ip="192.0.2.90", dest_ip="203.0.113.10", icmp_type="3",
          icmp_code="3")),
    ("313008", P + "%FTD-3-313008: Denied IPv6-ICMP type=130, code=0 from fe80::1 on interface dmz-1",
     dict(vendor_action="Denied", transport="IPv6-ICMP", icmp_type="130", icmp_code="0", src_ip="fe80::1",
          src_interface="dmz-1")),
    ("31707x", P + "%FTD-6-317077: Added STATIC route 192.0.2.0 255.255.255.0 via 192.0.2.1 [1/0] on [vpn-outside]",
     dict(route_action="Added", route_type="STATIC", route_network="192.0.2.0", route_mask="255.255.255.0",
          route_next_hop="192.0.2.1", route_distance="1", route_metric="0", route_interface="vpn-outside")),
    ("410001", P + "%FTD-4-410001: Dropped UDP DNS request from inside:192.0.2.100/53000 to outside:203.0.113.11/53; "
     "label length 105 bytes exceeds protocol limit of 63 bytes",
     dict(vendor_action="Dropped", transport="UDP", dns_message_type="request", src_ip="192.0.2.100",
          dest_port="53", reason="label length 105 bytes exceeds protocol limit of 63 bytes")),
    ("508002", P + "%FTD-4-508002: DCERPC response has low endpoint port 900 from inside:192.0.2.110/135 to "
     "outside:203.0.113.12/58115, terminating connection.",
     dict(dcerpc_endpoint_port="900", src_ip="192.0.2.110", src_port="135", dest_ip="203.0.113.12",
          dest_port="58115")),
    ("607002", P + "%FTD-4-607002: SIP Parameter: Received SIP Response 200 from outside:203.0.113.13/5060 to "
     "inside:192.0.2.120/49231; Found Other Media",
     dict(sip_action_class="SIP Parameter", sip_action="Received", sip_type="Response", sip_code="200",
          src_ip="203.0.113.13", dest_port="49231", sip_detail="Found Other Media")),
    ("7210xx", P + "%FTD-6-721016: (WebVPN-Secondary) WebVPN session for client user jdoe, IPv4 198.51.100.20 has been created.",
     dict(webvpn_role="WebVPN-Secondary", user="jdoe", src_ip="198.51.100.20", session_action="created")),
    ("722035", P + "%FTD-3-722035: Group <vpn-users> User <jdoe> IP <198.51.100.21> Received large packet 1550 (threshold 1390).",
     dict(group="vpn-users", user="jdoe", src_ip="198.51.100.21", packet_size="1550", packet_threshold="1390")),
    ("75xxxx_ikev2", P + "%FTD-5-750006: Local:203.0.113.1:500 Remote:198.51.100.30:500 Username:198.51.100.30 IKEv2 "
     "SA UP. Reason: New Connection Established",
     dict(dest_ip="203.0.113.1", dest_port="500", src_ip="198.51.100.30", src_port="500",
          ike_username="198.51.100.30", ike_message="SA UP", reason="New Connection Established")),
    ("752xxx", P + "%FTD-5-752004: Tunnel Manager dispatching a KEY_ACQUIRE message to IKEv2. Map Tag = vpn-map. "
     "Map Sequence Number = 10.",
     dict(crypto_map="vpn-map", crypto_map_seq="10")),
    ("10400x", P + "%FTD-1-104001: (Primary) Switching to ACTIVE - Other unit wants me Active. Secondary unit switch reason: Interface check.#012.",
     dict(failover_unit="Primary", failover_state="ACTIVE",
          reason="Other unit wants me Active. Secondary unit switch reason: Interface check")),
    ("10400x", P + "%FTD-1-104004: (Secondary) Switching to OK.", dict(failover_unit="Secondary", failover_state="OK", reason=None)),
    ("10500x_monitor", P + "%FTD-1-105003: (Primary) Monitoring on interface dmz-a waiting",
     dict(failover_unit="Primary", interface="dmz-a", monitor_status="waiting")),
    ("10500x_monitor", P + "%FTD-1-105004: (Secondary) Monitoring on interface partners normal",
     dict(failover_unit="Secondary", interface="partners", monitor_status="normal")),
    ("10500x_link", P + "%FTD-1-105007: (Primary) Link status 'Down' on interface servers",
     dict(failover_unit="Primary", link_status="Down", interface="servers")),
    ("41100x", P + "%FTD-4-411002: Line protocol on Interface Ethernet1/2, changed state to down",
     dict(interface="Ethernet1/2", interface_status="down")),
    ("72002x", P + "%FTD-6-720027: (VPN-Secondary) HA status callback: My state Standby Ready.",
     dict(ha_component="VPN", failover_unit="Secondary", ha_my_state="Standby Ready", ha_peer_state=None)),
    ("72002x", P + "%FTD-6-720028: (VPN-Primary) HA status callback: Peer state Failed.",
     dict(failover_unit="Primary", ha_peer_state="Failed", ha_my_state=None)),
    ("72003x", P + "%FTD-6-720032: (VPN-Primary) HA status callback: id=3,seq=200,grp=0,event=406,op=80,my=Active,peer=Standby Ready.",
     dict(ha_id="3", ha_seq="200", ha_group="0", ha_event="406", ha_op="80", ha_my_state="Active", ha_peer_state="Standby Ready")),
    ("72003x", P + "%FTD-6-720037: (VPN-Primary) HA progression callback: id=3,seq=200,grp=0,event=202,op=10,my=Active Applying Config,peer=Failed.",
     dict(ha_event="202", ha_my_state="Active Applying Config", ha_peer_state="Failed")),
    ("72003940", P + "%FTD-6-720040: (VPN-Secondary) VPN failover client is transitioning to standby state",
     dict(failover_unit="Secondary", ha_my_state="standby")),
    ("72100x", P + "%FTD-6-721002: (WebVPN-Primary) HA status change: event HA_STATUS_MY_STATE, my state Active, peer state Failed.",
     dict(ha_component="WebVPN", failover_unit="Primary", ha_event="HA_STATUS_MY_STATE", ha_my_state="Active", ha_peer_state="Failed")),
    ("72100x", P + "%FTD-6-721003: (WebVPN-Primary) HA progression change: event HA_PROG_ACTIVE_FAST, my state Just Active, peer state Failed.",
     dict(ha_event="HA_PROG_ACTIVE_FAST", ha_my_state="Just Active")),
    ("202010", P + "%FTD-3-202010: PAT pool exhausted in pool 'v4-0.0.0.0' IP 0.0.0.0, port range (1-65535). Unable to create UDP connection "
     "from inside:192.0.2.70/5060 to outside:203.0.113.40/5060.",
     dict(reason="PAT pool exhausted", nat_pool="v4-0.0.0.0", nat_pool_ip="0.0.0.0", nat_port_range="1-65535", transport="UDP",
          src_interface="inside", src_ip="192.0.2.70", src_port="5060", dest_ip="203.0.113.40", dest_port="5060")),
    ("20900x", P + "%FTD-4-209003: Fragment database limit of 200 exceeded:  src = 198.51.100.50, dest = 192.0.2.71, proto = IDRP, id = 17768",
     dict(reason="Fragment database limit", fragment_limit="200", src_ip="198.51.100.50", dest_ip="192.0.2.71", transport="IDRP",
          fragment_id="17768")),
    ("20900x", P + "%FTD-4-209005: Discard IP fragment set with more than 24 elements:  src = 192.0.2.72, dest = 239.255.10.10, proto = UDP, id = 23065",
     dict(reason="Discard IP fragment set", fragment_limit="24", transport="UDP", fragment_id="23065")),
    ("209006", P + "%FTD-3-209006: Fragment queue threshold exceeded, dropped <ip-prot-223> fragment from 198.51.100.51/554 to 192.0.2.73/34702 "
     "on dmz-inside interface.",
     dict(vendor_action="dropped", transport="<ip-prot-223>", src_ip="198.51.100.51", src_port="554", dest_ip="192.0.2.73",
          dest_port="34702", src_interface="dmz-inside")),
    ("210007", P + "%FTD-3-210007: LU allocate xlate failed for dynamic-pat UDP translation from inside:192.0.2.74/38708 (198.51.100.52/59376) "
     "to outside:203.0.113.41/53 (203.0.113.41/53) ",
     dict(nat_type="dynamic-pat", transport="UDP", src_ip="192.0.2.74", src_port="38708", src_translated_ip="198.51.100.52",
          src_translated_port="59376", dest_ip="203.0.113.41", dest_port="53", dest_translated_port="53")),
    ("210022", P + "%FTD-6-210022: LU missed 10049 updates", dict(lu_missed_updates="10049")),
    ("302037_inbound", P + "%FTD-6-302037: Built inbound IPINIP connection 19916343 from outside:203.0.113.42/0 to inside-gold:198.51.100.53/0",
     dict(vendor_action="Built", direction="inbound", transport="IPINIP", connection_id="19916343", src_interface="outside",
          src_ip="203.0.113.42", dest_interface="inside-gold", dest_ip="198.51.100.53")),
    ("302037_outbound", P + "%FTD-6-302037: Built outbound IPINIP connection 5 from outside:203.0.113.42/0 to inside:198.51.100.53/0",
     dict(direction="outbound", dest_ip="203.0.113.42", src_ip="198.51.100.53")),
    ("302038", P + "%FTD-6-302038: Teardown IPINIP connection 19916343 for outside:203.0.113.42/0 to inside-gold:198.51.100.53/0 duration 0:02:01 bytes 0",
     dict(vendor_action="Teardown", transport="IPINIP", connection_id="19916343", src_ip="203.0.113.42", dest_ip="198.51.100.53",
          duration="0:02:01", bytes="0")),
    ("508001", P + "%FTD-5-508001: DCERPC unknown non-standard major version 36 from vpn-a:198.51.100.54/58490 to vpn-b:192.0.2.75/135, terminating connection.",
     dict(reason="unknown non-standard major version", dcerpc_version="36", src_interface="vpn-a", src_ip="198.51.100.54",
          src_port="58490", dest_ip="192.0.2.75", dest_port="135")),
    ("713050", P + "%FTD-5-713050: Group = 203.0.113.43, IP = 203.0.113.43, Connection terminated for peer 203.0.113.43.  Reason: IPSec SA Idle "
     "Timeout  Remote Proxy 203.0.113.44, Local Proxy 198.51.100.55",
     dict(group="203.0.113.43", src_ip="203.0.113.43", reason="IPSec SA Idle Timeout", remote_proxy="203.0.113.44",
          local_proxy="198.51.100.55")),
    ("713257", P + "%FTD-5-713257: Phase 1 failure:  Mismatched attribute types for class Group Description:  Rcv'd: Group 1  Cfg'd: Group 14",
     dict(ike_phase="1", reason="Mismatched attribute types for class Group Description", ike_received="Group 1", ike_configured="Group 14")),
    ("713259", P + "%FTD-5-713259: Group = 203.0.113.43, IP = 203.0.113.43, Session is being torn down. Reason: User Requested",
     dict(group="203.0.113.43", src_ip="203.0.113.43", reason="User Requested")),
    ("713904", P + "%FTD-5-713904: IP = 203.0.113.43, Received encrypted packet with no matching SA, dropping",
     dict(src_ip="203.0.113.43", ike_message="Received encrypted packet with no matching SA, dropping")),
    ("713904", P + "%FTD-5-713904: IP = 203.0.113.45, Aggressive Mode connections disabled on interface... dropping pkt",
     dict(src_ip="203.0.113.45", ike_message="Aggressive Mode connections disabled on interface... dropping pkt")),
    ("716164", P + "%FTD-3-716164: SAML response relay state missing data integrity hash. Client IP: 203.0.113.46",
     dict(reason="SAML response relay state missing data integrity hash", src_ip="203.0.113.46")),
    ("722013", P + "%FTD-6-722013: Group <ra-vpn> User <jdoe@example.com> IP <203.0.113.47> SVC Message: 17/INFO: The VPN connection is being "
     "paused without restrictions..",
     dict(group="ra-vpn", user="jdoe@example.com", src_ip="203.0.113.47", svc_message_id="17", svc_severity="INFO",
          svc_message="The VPN connection is being paused without restrictions")),
    ("121003", P + "%FTD-6-121003: 14:08:17 CST Nov 4 2026: msgId 55. Telemetry request from the chassis received. SSE connector status: enabled. "
     "Telemetry config on the blade: enabled. Telemetry data collected#012",
     dict(telemetry_msg_id="55", telemetry_message="Telemetry request from the chassis received.", sse_connector_status="enabled",
          telemetry_blade_config="enabled", telemetry_result="Telemetry data collected")),
    ("19902x", P + "%FTD-6-199022: Backup operation started at 08:03:11 UTC Wed Nov 4 2026 . Target location: disk0:/running_configuration_file",
     dict(backup_status="started", backup_time="08:03:11 UTC Wed Nov 4 2026", backup_target="disk0:/running_configuration_file")),
    ("19902x", P + "%FTD-6-199024: Backup operation finished at 08:03:12 UTC Wed Nov 4 2026 .",
     dict(backup_status="finished", backup_time="08:03:12 UTC Wed Nov 4 2026", backup_target=None)),
    ("447001", P + "%FTD-4-447001: ASP DP to CP Punt Event Queue was full. Queue length 2048, limit 2048",
     dict(queue_name="Punt Event Queue", queue_length="2048", queue_limit="2048")),
    ("717004", P + "%FTD-6-717004: PKCS #12 export failed for trustpoint Example_Trustpoint.", dict(trustpoint="Example_Trustpoint")),
    ("19901x_fprm", P + "%FTD-4-199016:  FPRM: <<%FPRM-4-LINK_DOWN>> [F1150][cleared][link-down][sys/switch-A/slot-1/switch-ether/port-3] ether port "
     "1/3 on fabric interconnect A oper state: link-down, reason: Down#012",
     dict(fprm_severity="4", fprm_event="LINK_DOWN")),
    ("199018_audit", P + "%FTD-6-199018:  FPRM: <<%FPRM-6-AUDIT>> [session][internal][creation][internal][121678][sys/user-ext/sh-login-admin-pts_0_1_1]"
     "[id:pts_0_1_1, name:admin, policyOwner:local][] Fabric A: local user admin logged in from 192.0.2.76#012",
     dict(fprm_audit_type="session", fprm_audit_user="internal", fprm_audit_action="creation", fprm_audit_cause="internal",
          fprm_audit_id="121678")),
    ("199018_login", P + "%FTD-6-199018:  FPRM: <<%FPRM-6-AUDIT>> [session][internal][creation][internal][121678][x][y][] Fabric A: local user admin "
     "logged in from 192.0.2.76#012",
     dict(user="admin", src_ip="192.0.2.76")),
    ("199018_cmd", P + "%FTD-6-199018:  FPRM: <<%FPRM-6-AUDIT>> [admin][admin][modification][internal][121679][aaa-log][aaa-log][] switch A: cmd: "
     "connect ftd , logged in from 192.0.2.76 on term /dev/pts/0: Local mgmt command executed#012",
     dict(command="connect ftd", src_ip="192.0.2.76")),
    ("199018_logout", P + "%FTD-6-199018:  FPRM: <<%FPRM-6-AUDIT>> [session][internal][deletion][internal][121680][x][y][] Fabric A: system "
     "terminated session id pts_0_1_1 of user admin due to idle timeout#012",
     dict(session_id="pts_0_1_1", user="admin", reason="idle timeout")),
    ("19901x_process", P + "%FTD-4-199016:  kernel: [1780755.148147] pci 0000:81:00.0: PCIe Bus Error: severity=Corrected#012",
     dict(process_name="kernel")),
]
# extractions meant to run together on the same message (199017: process name on every line, plus sudo)
_FTX = {"19901x_process", "19901x_fprm", "199018_audit", "199018_login", "199018_cmd", "199018_logout"}
ALLOWED_OVERLAP = {("199017_sudo", "19901x_process")} | {(a, b) for a in _FTX for b in _FTX if a != b}
NEGATIVE = [                                     # lines no extraction of this app may match
    ("75xxxx_ikev2", P + "%FTD-6-751025: Local:203.0.113.1:500 Remote:198.51.100.30:500 Username:x IKEv2 Group:G "
     "IPv4 Address=192.0.2.5 assigned to Session"),
    ("*", P + "%FTD-6-302013: Built inbound TCP connection 1 for outside:203.0.113.9/1 (203.0.113.9/1) to "
     "inside:192.0.2.80/22 (192.0.2.80/22)"),
]


def extracts():
    out, stanza = {}, None
    for line in open(os.path.join(APP, "default", "props.conf"), encoding="utf-8"):
        s = line.strip()
        if s.startswith("["):
            stanza = s
        elif s.startswith("EXTRACT-ftdx_"):
            key, value = (x.strip() for x in s.split("=", 1))
            assert stanza == "[cisco:asa]", f"{key} is outside [cisco:asa]"
            out[key[len("EXTRACT-ftdx_"):]] = re.compile(re.sub(r"\(\?<(?=[A-Za-z_])", "(?P<", value))
    return out


def main():
    rules = extracts()
    fails = []
    tested = set()
    for rule, line, want in SAMPLES:
        tested.add(rule)
        rx = rules.get(rule)
        m = rx.search(line) if rx else None
        got = {k: v for k, v in (m.groupdict() if m else {}).items()}
        bad = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
        others = [r for r, x in rules.items() if r != rule and x.search(line) and (rule, r) not in ALLOWED_OVERLAP]
        ok = m is not None and not bad and not others
        print(("PASS  " if ok else "FAIL  ") + f"{rule}: {line.split(': ', 1)[1][:70]}")
        if not ok:
            fails.append(rule)
            print("      mismatched:", bad, "also matched by:", others)
    for rule, line in NEGATIVE:
        hit = [r for r, x in rules.items() if x.search(line) and (rule == "*" or r == rule)]
        print(("PASS  " if not hit else "FAIL  ") + f"no match: {line.split(': ', 1)[1][:60]} {hit or ''}")
        if hit:
            fails.append("negative " + rule)
    untested = sorted(set(rules) - tested)
    print(("PASS  " if not untested else "FAIL  ") + f"every extraction has a sample {untested or ''}")
    if untested:
        fails.append("untested")
    print("\nALL PASSED" if not fails else f"\n{len(fails)} failed")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
