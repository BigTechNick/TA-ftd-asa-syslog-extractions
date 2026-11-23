#!/usr/bin/env python3
"""
cim_fix_test.py - offline checks for the 1.1.0 CIM fixes for the Cisco Security Cloud app.

The fixes only work if they never reuse a setting the Cisco Security Cloud app sets (Cisco's
default settings outrank this add-on). This checks that, and that the action lookup and the
replacement event types say what the README says.
"""
import csv
import os
import re
import sys

APP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "TA-ftd-asa-syslog-extractions")

# Keys the Cisco Security Cloud app (4.1.3) sets in these stanzas that this add-on must not reuse.
CISCO_EVALS = {
    "cisco:ftd:syslog": {
        "AC_RuleAction", "ClientApplication", "InitiatorIP", "InitiatorPort", "IntrusionRuleMessage",
        "ResponderIP", "ResponderPort", "action", "bytes", "client_version", "dest", "dest_ip",
        "duration", "gid", "id_orig_h", "id_resp_h", "ids_type", "logtype", "msg", "refs", "sid",
        "vendor_product",
    },
    "cisco:sfw:estreamer": {"action"},
}
CISCO_PREFIXES = ("FIELDALIAS-syslog_", "FIELDALIAS-estreamer_", "LOOKUP-cisco_", "REPORT-", "EXTRACT-extract_")

DISABLED = {
    "cisco_syslog_ConnectionEvent_begin_connect", "cisco_syslog_ConnectionEvent_end_connect",
    "cisco_syslog_FileEvent", "cisco_estreamer_FileEvent", "cisco_estreamer_FileEvent_malware",
    "cisco_asa_network_sessions",
}

# Action values seen from Cisco Security Cloud for cisco:ftd:syslog and cisco:sfw:estreamer, and
# the values Cisco's own lookups produce, with the CIM value each must end up as.
EXPECTED = {
    "Allow": "allowed", "Trust": "allowed", "Fastpath": "allowed", "Monitor": "allowed",
    "Alert": "allowed", "Block": "blocked", "Block with reset": "blocked",
    "Interactive Block": "blocked", "Interactive Block with Reset": "blocked",
    "allowed": "allowed", "blocked": "blocked", "teardown": "teardown", "unknown": "unknown",
    "Would block": "allowed", "Dropped": "blocked", "Malware Block": "blocked", "Detect": "allowed",
}
CIM_ACTIONS = {"allowed", "blocked", "teardown", "unknown"}

FAILS = []


def check(ok, msg):
    print(("PASS  " if ok else "FAIL  ") + msg)
    if not ok:
        FAILS.append(msg)


def conf(name):
    out, stanza = {}, None
    path = os.path.join(APP, "default", name)
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[") and s.endswith("]"):
            stanza = s[1:-1]
            out.setdefault(stanza, {})
        elif "=" in s:
            k, v = (x.strip() for x in s.split("=", 1))
            out[stanza][k] = v
    return out


def main():
    props = conf("props.conf")
    for stanza, evals in CISCO_EVALS.items():
        keys = props.get(stanza, {})
        check(bool(keys), f"props.conf has [{stanza}]")
        for key in keys:
            reused = (key.startswith("EVAL-") and key[5:] in evals) or key.startswith(CISCO_PREFIXES)
            check(not reused, f"[{stanza}] {key} is not a key Cisco Security Cloud sets")
    ftd = props["cisco:ftd:syslog"]
    check(ftd.get("EVAL-src", "").startswith("coalesce(SrcIP"), "src comes from the initiator IP first")
    check("ReferencedHost" not in ftd.get("EVAL-src", ""), "src never falls back to ReferencedHost")
    check(ftd.get("FIELDALIAS-ftdx_signature") == "Message ASNEW signature", "signature from Message")
    sev = ftd.get("EVAL-severity", "")
    check(all(x in sev for x in ('"high"', '"medium"', '"low"', '"informational"')), "severity uses CIM words")
    for stanza in CISCO_EVALS:
        check(props[stanza].get("LOOKUP-ftdx_cim_action") == "ftdx_cim_action_lookup vendor_value AS action OUTPUT action",
              f"[{stanza}] action goes through the lookup")

    check(ftd.get("LOOKUP-ftdx_cim_file_action") == "ftdx_cim_action_lookup vendor_value AS FileAction OUTPUTNEW action",
          "file events: action from FileAction only where empty (OUTPUTNEW)")

    transforms = conf("transforms.conf")
    lk = transforms.get("ftdx_cim_action_lookup", {})
    check(lk.get("case_sensitive_match") == "false", "lookup matches without regard to case")
    rows = list(csv.DictReader(open(os.path.join(APP, "lookups", lk.get("filename", "missing.csv")), encoding="utf-8")))
    check(rows and list(rows[0]) == ["vendor_value", "action"], "lookup header is vendor_value,action")
    table = {}
    for r in rows:
        key = r["vendor_value"].lower()
        check(key not in table, f"lookup value {r['vendor_value']!r} listed once")
        table[key] = r["action"]
    bad = sorted(v for v in set(table.values()) if v not in CIM_ACTIONS)
    check(not bad, f"lookup outputs only CIM actions {bad or ''}")
    for raw, want in EXPECTED.items():
        check(table.get(raw.lower()) == want, f"{raw!r} -> {want}")

    et = conf("eventtypes.conf")
    for name in sorted(DISABLED):
        check(et.get(name) == {"disabled": "1"}, f"{name} only sets disabled = 1")
    mal = et.get("ftdx_estreamer_malware", {}).get("search", "")
    check("SHA_Disposition=Malware" in mal and "Unknown" not in mal, "eStreamer malware: Malware verdict only")
    check("EventType=FileMalwareEvent" in mal, "eStreamer malware: includes FileMalwareEvent")
    ses = et.get("ftdx_asa_network_sessions", {}).get("search", "")
    ids = set(re.findall(r'message_id="(\d+)"', ses))
    check(ids and not ids & {"725003", "725007"}, "ASA sessions: no 725003 / 725007")
    check({"722028", "722029", "722030", "722031", "722037", "751025"} <= ids, "ASA sessions: VPN session IDs kept")

    tags = conf("tags.conf")
    for stanza in tags:
        name = stanza.split("=", 1)[1]
        check(name.startswith("ftdx_") and name in et, f"tags.conf [{stanza}] is one of this add-on's event types")
    check(tags.get("eventtype=ftdx_estreamer_malware") == {"alert": "enabled", "attack": "enabled", "malware": "enabled"},
          "eStreamer malware tags: alert attack malware")
    check(tags.get("eventtype=ftdx_asa_network_sessions") == {"network": "enabled", "session": "enabled"},
          "ASA sessions tags: network session")

    print("\nALL PASSED" if not FAILS else f"\n{len(FAILS)} failed")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
