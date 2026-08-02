#!/usr/bin/env python3
"""Read-only FortiGate hardening checks over the FortiOS REST API."""

import argparse
import datetime as dt
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASELINES = {
    "8.0": {
        "label": "FortiOS 8.0",
        "url": "https://docs.fortinet.com/document/fortigate/8.0.0/best-practices/555436/hardening",
        "generated_private_key": True,
    },
    "7.6": {
        "label": "FortiOS 7.6",
        "url": "https://docs.fortinet.com/document/fortigate/7.6.0/best-practices/555436",
        "generated_private_key": None,  # Behavior changes at 7.6.1.
    },
    "7.4": {
        "label": "FortiOS 7.4",
        "url": "https://docs.fortinet.com/document/fortigate/7.4.0/best-practices/555436",
        "generated_private_key": False,
    },
}

ENDPOINTS = {
    "status": ["/api/v2/monitor/system/status"],
    "global": ["/api/v2/cmdb/system/global"],
    "interfaces": ["/api/v2/cmdb/system/interface"],
    "admins": ["/api/v2/cmdb/system/admin"],
    "api_users": ["/api/v2/cmdb/system/api-user"],
    "ntp": ["/api/v2/cmdb/system/ntp"],
    "autoinstall": ["/api/v2/cmdb/system/auto-install"],
    "snmp_info": ["/api/v2/cmdb/system.snmp/sysinfo", "/api/v2/cmdb/system/snmp/sysinfo"],
    "snmp_communities": ["/api/v2/cmdb/system.snmp/community", "/api/v2/cmdb/system/snmp/community"],
    "snmp_users": ["/api/v2/cmdb/system.snmp/user", "/api/v2/cmdb/system/snmp/user"],
    "fortianalyzer": ["/api/v2/cmdb/log.fortianalyzer/setting", "/api/v2/cmdb/log/fortianalyzer/setting"],
    "syslog": ["/api/v2/cmdb/log.syslogd/setting", "/api/v2/cmdb/log/syslogd/setting"],
    "syslog2": ["/api/v2/cmdb/log.syslogd2/setting", "/api/v2/cmdb/log/syslogd2/setting"],
    "syslog3": ["/api/v2/cmdb/log.syslogd3/setting", "/api/v2/cmdb/log/syslogd3/setting"],
    "local_in": ["/api/v2/cmdb/firewall/local-in-policy"],
    "dos": ["/api/v2/cmdb/firewall/DoS-policy", "/api/v2/cmdb/firewall/dos-policy"],
    "policies": ["/api/v2/cmdb/firewall/policy"],
    "ldap": ["/api/v2/cmdb/user/ldap"],
    "radius": ["/api/v2/cmdb/user/radius"],
    "ospf": ["/api/v2/cmdb/router/ospf"],
    "ssl_vpn": ["/api/v2/cmdb/vpn.ssl/settings", "/api/v2/cmdb/vpn/ssl/settings"],
    "ipsec": ["/api/v2/cmdb/vpn.ipsec/phase1-interface", "/api/v2/cmdb/vpn/ipsec/phase1-interface"],
    "license": ["/api/v2/monitor/license/status", "/api/v2/monitor/system/license/status"],
}

DOS_ANOMALIES = (
    "tcp_syn_flood", "tcp_port_scan", "tcp_src_session",
    "tcp_dst_session", "ip_src_session", "ip_dst_session",
)


def norm(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "enable" if value else "disable"
    return str(value).strip().lower()


def enabled(value):
    return value is not None and norm(value) in {"enable", "enabled", "true", "yes", "1", "on"}


def disabled(value):
    return value is not None and norm(value) in {"disable", "disabled", "false", "no", "0", "off"}


def rows(value):
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []


def field(obj, *names, default=None):
    for key in names:
        if isinstance(obj, dict) and key in obj:
            return obj[key]
    return default


def name(value):
    return str(field(value, "name", "q_origin_key", "mkey", "policyid", "id", default="unknown"))


def named_values(value):
    if isinstance(value, list):
        return [name(item) if isinstance(item, dict) else str(item) for item in value]
    if isinstance(value, dict):
        return [name(value)]
    return [] if value is None else [str(value)]


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def recursive_values(value, wanted_keys):
    wanted = {key.lower() for key in wanted_keys}
    found = []
    for obj in walk_dicts(value):
        for key, item in obj.items():
            if str(key).lower() in wanted:
                if isinstance(item, list):
                    found.extend(item)
                else:
                    found.append(item)
    return found


def active(obj):
    """FortiOS table entries default to enabled when status is omitted."""
    status = field(obj, "status")
    return not disabled(status) if status is not None else True


def desired_setting(obj, names, predicate):
    value = field(obj, *names)
    if value is None:
        return None, "not returned"
    try:
        return bool(predicate(value)), value
    except (TypeError, ValueError):
        return None, value


def trusthosts(obj):
    hosts = []
    for candidate in walk_dicts(obj):
        for key, value in candidate.items():
            lowered = str(key).lower()
            if "trusthost" in lowered or lowered in {"ipv4-trusthost", "ipv6-trusthost"}:
                if isinstance(value, (str, int)):
                    hosts.append(str(value))
    return hosts


def unrestricted_host(value):
    compact = " ".join(str(value).lower().split())
    return compact in {"0.0.0.0 0.0.0.0", "0.0.0.0/0", "::/0", "0::0/0"}


def has_restricted_trusthost(obj):
    hosts = [host for host in trusthosts(obj) if host and norm(host) not in {"none", "null"}]
    return bool(hosts) and any(not unrestricted_host(host) for host in hosts)


def explicit_tls(obj):
    modes = [norm(value) for value in recursive_values(obj, {"mode", "transport-protocol", "protocol"})]
    encryption = [norm(value) for value in recursive_values(obj, {
        "enc-algorithm", "enc_algorithm", "ssl-min-proto-version", "ssl-min-proto-ver",
        "server-cert", "certificate", "certificate-verification",
    })]
    return "tls" in modes or "radsec" in modes or any(
        value not in {"", "none", "disable", "disabled", "default"} for value in encryption
    )


class Scanner:
    def __init__(self, args, token):
        self.args = args
        self.token = token
        self.data = {}
        self.results = []
        self.context = ssl.create_default_context() if args.verify_tls else ssl._create_unverified_context()

    def fetch(self, path):
        query = urllib.parse.urlencode({"vdom": self.args.vdom})
        url = f"https://{self.args.host}:{self.args.port}{path}?{query}"
        request = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": "shark-jack-fortigate-hardening/2.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=self.args.timeout, context=self.context) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
                if isinstance(payload, dict) and norm(payload.get("status", "success")) in {"error", "fail", "failed"}:
                    return {"ok": False, "endpoint": path, "error": payload.get("message", "API error"), "data": payload}
                return {"ok": True, "endpoint": path, "http_status": response.status, "data": payload}
        except urllib.error.HTTPError as exc:
            return {"ok": False, "endpoint": path, "http_status": exc.code, "error": f"HTTP {exc.code}"}
        except Exception as exc:
            return {"ok": False, "endpoint": path, "error": str(exc)}

    def collect(self):
        for key, candidates in ENDPOINTS.items():
            last = None
            for endpoint in candidates:
                last = self.fetch(endpoint)
                if last["ok"]:
                    break
            self.data[key] = last

    def available(self, key):
        return bool(self.data.get(key) and self.data[key].get("ok"))

    def value(self, key):
        endpoint = self.data.get(key) or {}
        if not endpoint.get("ok"):
            return None
        value = endpoint.get("data")
        return value.get("results") if isinstance(value, dict) and "results" in value else value

    def add(self, status, control_id, severity, description, evidence, recommendation=""):
        self.results.append({
            "status": status, "control_id": control_id, "severity": severity,
            "description": description, "evidence": str(evidence), "recommendation": recommendation,
        })

    def boolean(self, passed, control_id, severity, description, evidence, recommendation):
        status = "REVIEW" if passed is None else "PASS" if passed else "FAIL"
        self.add(status, control_id, severity, description, evidence, recommendation)

    def missing(self, key, control_id, severity, label):
        endpoint = self.data.get(key) or {}
        self.add("REVIEW", control_id, severity, label,
                 f"Endpoint unavailable: {endpoint.get('error', 'no data')}",
                 "Grant the read-only API profile access or review manually.")

    def manual(self, control_id, severity, description, recommendation):
        self.add("REVIEW", control_id, severity, description,
                 "Operational or external evidence is required.", recommendation)

    def run_checks(self):
        baseline = BASELINES[self.args.baseline]
        self.check_firmware(baseline)
        self.check_global(baseline)
        self.check_interfaces()
        self.check_admins()
        self.check_api_users()
        self.check_time()
        self.check_logging()
        self.check_local_in()
        self.check_physical()
        self.check_encrypted_protocols()
        self.check_dos()
        self.check_policies()
        self.check_vpn()
        self.check_fortiguard()
        self.add_manual_controls()

    def check_firmware(self, baseline):
        self.manual("FG-HARD-002", "High", "Firmware is on a current supported patch release",
                    "Confirm the latest recommended patch, PSIRT exposure, upgrade path, and FortiOS lifecycle status.")
        if not self.available("status"):
            self.missing("status", "FG-HARD-001", "High", "Firmware family matches the selected baseline")
            return
        status = rows(self.value("status"))
        if not status:
            self.boolean(None, "FG-HARD-001", "High", "Firmware family matches the selected baseline",
                         "Status endpoint returned no version", "Review the installed FortiOS version.")
            return
        version = str(field(status[0], "version", "Version", default=""))
        family_match = bool(version) and version.startswith((f"v{self.args.baseline}", self.args.baseline))
        self.boolean(family_match, "FG-HARD-001", "High", "Firmware family matches the selected baseline",
                     f"selected={baseline['label']}; detected={version or 'unknown'}",
                     "Select the matching baseline or install the intended FortiOS train.")
    def check_global(self, baseline):
        if not self.available("global"):
            self.missing("global", "API-GLOBAL", "High", "Global hardening settings can be validated")
            return
        global_rows = rows(self.value("global"))
        if not global_rows:
            self.boolean(None, "API-GLOBAL", "High", "Global hardening settings can be validated",
                         "Endpoint returned no object", "Review API permissions and response schema.")
            return
        obj = global_rows[0]
        checks = [
            (*desired_setting(obj, ("strong-crypto", "strong_crypto"), enabled), "FG-CRYPTO-001", "High", "Strong crypto is enabled", "Enable strong-crypto."),
            (*desired_setting(obj, ("ssl-static-key-ciphers", "ssl_static_key_ciphers"), disabled), "FG-CRYPTO-002", "High", "Static-key TLS ciphers are disabled", "Disable ssl-static-key-ciphers."),
            (*desired_setting(obj, ("dh-params", "dh_params"), lambda value: str(value) == "8192"), "FG-CRYPTO-003", "Medium", "DH parameters are 8192", "Set dh-params to 8192 where supported."),
            (*desired_setting(obj, ("admin-sport", "admin_sport"), lambda value: str(value) != "443"), "FG-MGMT-012", "Medium", "HTTPS admin port is non-standard", "Use a restricted non-default HTTPS port."),
            (*desired_setting(obj, ("admin-ssh-port", "admin_ssh_port"), lambda value: str(value) != "22"), "FG-MGMT-013", "Medium", "SSH admin port is non-standard", "Use a restricted non-default SSH port."),
            (*desired_setting(obj, ("admintimeout", "admin-timeout"), lambda value: int(value) < 10), "FG-MGMT-016", "Medium", "Admin idle timeout is under 10 minutes", "Set the administrator timeout below 10 minutes."),
            (*desired_setting(obj, ("private-data-encryption", "private_data_encryption"), enabled), "FG-PWD-001", "Medium", "Private-data encryption is enabled", "Enable private-data-encryption after reviewing backup and RMA implications."),
            (*desired_setting(obj, ("admin-scp", "admin_scp"), enabled), "FG-ENC-005", "Low", "Administrative SCP is enabled for secure file transfer", "Use SCP rather than FTP or TFTP for administrative transfers."),
        ]
        for passed, evidence, control_id, severity, description, recommendation in checks:
            self.boolean(passed, control_id, severity, description, evidence, recommendation)
        if baseline["generated_private_key"] is True:
            note = "FortiOS 7.6.1+ generates the private-data-encryption password; confirm backup and RMA recovery procedures."
        elif baseline["generated_private_key"] is False:
            note = "FortiOS 7.4 requires controlled custody of the configured private encryption key."
        else:
            note = "Determine whether the device is before or after 7.6.1 and validate the corresponding key and RMA process."
        self.add("REVIEW", "FG-PWD-002", "Medium", "Private-data-encryption recovery process is documented", note,
                 "Test encrypted backup restoration and document HA/RMA key handling.")

    def check_interfaces(self):
        if not self.available("interfaces"):
            self.missing("interfaces", "API-INTERFACES", "High", "Management-interface exposure can be validated")
            return
        interfaces = rows(self.value("interfaces"))
        insecure, external_admin, admin_interfaces = [], [], []
        for interface in interfaces:
            access = {token.lower() for raw in named_values(field(interface, "allowaccess", "allow-access"))
                      for token in re.split(r"[ ,]+", raw) if token}
            interface_name = name(interface)
            if access & {"http", "telnet"}:
                insecure.append(interface_name)
            if access & {"https", "ssh", "http", "telnet"}:
                admin_interfaces.append(interface_name)
            role = norm(field(interface, "role", "interface-role"))
            is_external = role == "wan" or bool(re.search(r"wan|internet|outside|uplink", interface_name, re.I))
            if is_external and access & {"https", "ssh", "http", "telnet"}:
                external_admin.append(interface_name)
        self.boolean(not insecure, "FG-MGMT-005", "High", "HTTP and Telnet are disabled on interfaces",
                     insecure or "none", "Remove HTTP and Telnet from interface allowaccess.")
        self.boolean(not external_admin, "FG-MGMT-003", "High", "External interfaces do not directly expose administration",
                     external_admin or "none", "Use a dedicated management network; if unavoidable, require trusted hosts and a restrictive logged local-in policy.")
        self.boolean(True if len(admin_interfaces) <= 2 else None, "FG-MGMT-001", "Medium",
                     "Administrative access is concentrated on dedicated interfaces", admin_interfaces,
                     "Review whether every administrative interface is required and appropriately isolated.")

    def check_admins(self):
        if not self.available("admins"):
            self.missing("admins", "API-ADMINS", "High", "Administrator posture can be validated")
            return
        admins = rows(self.value("admins"))
        if not admins:
            self.boolean(None, "API-ADMINS", "High", "Administrator posture can be validated",
                         "No administrators returned", "Review API permissions.")
            return
        defaults, unrestricted, no_mfa, supers = [], [], [], []
        for admin in admins:
            admin_name = name(admin)
            if admin_name.lower() in {"admin", "administrator", "root"}:
                defaults.append(admin_name)
            if not has_restricted_trusthost(admin):
                unrestricted.append(admin_name)
            if not enabled(field(admin, "remote-auth", "remote_auth", default="disable")) and disabled(field(admin, "two-factor", "two_factor", default="disable")):
                no_mfa.append(admin_name)
            if norm(field(admin, "accprofile", "profile")) == "super_admin":
                supers.append(admin_name)
        self.boolean(not defaults, "FG-MGMT-014", "Medium", "Default administrator names are not used",
                     defaults or "none", "Use unique, non-guessable named accounts.")
        self.boolean(not unrestricted, "FG-ADMIN-004", "High", "Administrator trusted hosts are restricted",
                     unrestricted or "none", "Configure restricted trusted hosts for every administrator.")
        self.boolean(not no_mfa, "FG-ADMIN-006", "High", "MFA is enabled for local administrators",
                     no_mfa or "none", "Enable MFA or centralized authentication with MFA.")
        self.boolean(True if len(supers) <= 1 else None, "FG-ADMIN-007", "Medium", "Super-admin use is minimized",
                     supers or "none", "Review each super_admin assignment and use least-privilege profiles.")

    def check_api_users(self):
        if not self.available("api_users"):
            self.missing("api_users", "API-USERS", "High", "REST API account posture can be validated")
            return
        api_users = rows(self.value("api_users"))
        unrestricted = [name(user) for user in api_users if not has_restricted_trusthost(user)]
        supers = [name(user) for user in api_users if norm(field(user, "accprofile", "profile")) == "super_admin"]
        self.boolean(not unrestricted, "FG-API-001", "High", "API users have restricted trusted hosts",
                     unrestricted or "none", "Restrict every API user to approved sources.")
        self.boolean(not supers, "FG-API-002", "High", "API users avoid super_admin",
                     supers or "none", "Use a custom read-only API profile.")

    def check_time(self):
        if not self.available("ntp"):
            self.missing("ntp", "FG-TIME-001", "High", "NTP posture can be validated")
            return
        ntp_rows = rows(self.value("ntp"))
        if not ntp_rows:
            self.boolean(None, "FG-TIME-001", "High", "NTP synchronization is enabled", "No NTP data", "Enable NTP.")
            return
        obj = ntp_rows[0]
        sync = field(obj, "ntpsync", "ntp-sync", "status")
        self.boolean(None if sync is None else enabled(sync), "FG-TIME-001", "High", "NTP synchronization is enabled",
                     f"ntpsync/status={sync}", "Enable NTP synchronization.")
        auth_values = recursive_values(obj, {"authentication", "auth", "ntp-auth"})
        auth_result = None if not auth_values else all(enabled(value) for value in auth_values)
        self.boolean(auth_result, "FG-TIME-005", "Medium", "Configured NTP servers use authentication",
                     auth_values or "authentication fields not returned", "Enable NTP authentication where supported.")

    def check_logging(self):
        keys = ("fortianalyzer", "syslog", "syslog2", "syslog3")
        available = [key for key in keys if self.available(key)]
        if not available:
            self.missing("fortianalyzer", "FG-LOG-001", "High", "Centralized logging can be validated")
            self.boolean(None, "FG-LOG-006", "High", "Remote logging uses encrypted transport",
                         "No logging endpoint available", "Grant access to logging settings.")
            return
        targets = []
        for key in available:
            for target in rows(self.value(key)):
                if enabled(field(target, "status")):
                    targets.append((key, target))
        self.boolean(bool(targets), "FG-LOG-001", "High", "Centralized logging is configured",
                     [key for key, _ in targets] or "no enabled target", "Send logs to FortiAnalyzer or secured syslog.")
        if not targets:
            encrypted_result = None
            encrypted_evidence = "No enabled remote target"
        else:
            secure = [key for key, target in targets if explicit_tls(target)]
            encrypted_result = True if len(secure) == len(targets) else None
            encrypted_evidence = f"enabled={[key for key, _ in targets]}; explicit TLS={secure or 'none'}"
        self.boolean(encrypted_result, "FG-LOG-006", "High", "Remote logging uses explicitly encrypted transport",
                     encrypted_evidence, "Verify TLS/encryption and certificate validation for every remote log target.")

    def check_local_in(self):
        if not self.available("local_in"):
            self.missing("local_in", "FG-LIN-001", "High", "Local-in policy posture can be validated")
            return
        active_policies = [policy for policy in rows(self.value("local_in")) if active(policy)]
        self.boolean(bool(active_policies), "FG-LIN-001", "High", "Active local-in policies are configured",
                     f"active count={len(active_policies)}", "Restrict administrative services with local-in policies.")
        if not active_policies:
            self.boolean(False, "FG-LIN-003", "High", "Local-in allow policies restrict source addresses",
                         "No active local-in policies", "Allow only trusted management sources.")
            self.boolean(False, "FG-LIN-005", "Medium", "Local-in policy logging is enabled",
                         "No active local-in policies", "Enable logging on management local-in policies.")
            return
        accepting = [policy for policy in active_policies if norm(field(policy, "action", default="accept")) == "accept"]
        broad = []
        for policy in accepting:
            sources = [norm(value) for value in named_values(field(policy, "srcaddr", "srcaddr6", "source"))]
            if not sources or any(value in {"all", "all_ipv4", "all_ipv6", "0.0.0.0/0", "::/0"} for value in sources):
                broad.append(name(policy))
        logged = [name(policy) for policy in active_policies if enabled(field(policy, "logtraffic", "log", "logtraffic-start"))]
        self.boolean(not broad, "FG-LIN-003", "High", "Local-in allow policies restrict source addresses",
                     broad or "none", "Replace broad sources with trusted management hosts or groups.")
        self.boolean(len(logged) == len(active_policies), "FG-LIN-005", "Medium", "Local-in policy logging is enabled",
                     f"active={len(active_policies)}; logged={len(logged)}", "Enable logging on active local-in policies.")

    def check_physical(self):
        if not self.available("autoinstall"):
            self.missing("autoinstall", "API-AUTOINSTALL", "High", "USB auto-install posture can be validated")
            return
        values = rows(self.value("autoinstall"))
        if not values:
            self.boolean(None, "FG-PHYS-002", "High", "USB configuration auto-install is disabled", "No data", "Review manually.")
            self.boolean(None, "FG-PHYS-003", "High", "USB image auto-install is disabled", "No data", "Review manually.")
            return
        obj = values[0]
        for key, control_id, description in (
            ("auto-install-config", "FG-PHYS-002", "USB configuration auto-install is disabled"),
            ("auto-install-image", "FG-PHYS-003", "USB image auto-install is disabled"),
        ):
            value = field(obj, key)
            self.boolean(None if value is None else disabled(value), control_id, "High", description,
                         f"{key}={value if value is not None else 'not returned'}", f"Set {key} disable.")

    def check_encrypted_protocols(self):
        if not self.available("snmp_info"):
            self.missing("snmp_info", "FG-ENC-004", "High", "SNMP posture can be validated")
        else:
            info = rows(self.value("snmp_info"))
            snmp_status = field(info[0], "status") if info else None
            if snmp_status is None:
                self.boolean(None, "FG-ENC-004", "High", "SNMPv3 is used or SNMP is disabled",
                             "SNMP status not returned", "Verify SNMP status and remove v1/v2c communities.")
            elif disabled(snmp_status):
                self.boolean(True, "FG-ENC-004", "High", "SNMPv3 is used or SNMP is disabled",
                             "SNMP disabled", "")
            elif not self.available("snmp_communities") or not self.available("snmp_users"):
                self.boolean(None, "FG-ENC-004", "High", "SNMPv3 is used or SNMP is disabled",
                             "Community or user endpoint unavailable", "Grant API access and verify SNMPv3.")
            else:
                communities = [item for item in rows(self.value("snmp_communities")) if active(item)]
                users = [item for item in rows(self.value("snmp_users")) if active(item)]
                self.boolean(not communities and bool(users), "FG-ENC-004", "High", "SNMPv3 is used or SNMP is disabled",
                             f"active communities={len(communities)}; active v3 users={len(users)}", "Remove SNMP communities and use SNMPv3.")

        if not self.available("ldap"):
            self.missing("ldap", "FG-ENC-001", "High", "LDAP transport can be validated")
        else:
            ldap_objects = rows(self.value("ldap"))
            insecure = []
            for item in ldap_objects:
                secure = norm(field(item, "secure", "ssl", "tls"))
                if secure not in {"ldaps", "starttls", "enable", "enabled", "yes"}:
                    insecure.append(name(item))
            self.boolean(not insecure, "FG-ENC-001", "High", "LDAP uses LDAPS or STARTTLS",
                         insecure or "none", "Use LDAPS or STARTTLS and least-privilege bind credentials.")

        if not self.available("radius"):
            self.missing("radius", "FG-ENC-003", "Medium", "RADIUS transport can be validated")
        else:
            radius_objects = rows(self.value("radius"))
            insecure = [name(item) for item in radius_objects if not explicit_tls(item)]
            result = True if not radius_objects else not insecure
            self.boolean(result, "FG-ENC-003", "Medium", "RADIUS uses RADSEC/TLS where supported",
                         insecure or "none", "Use RADSEC/TLS where supported by the identity infrastructure.")

        if not self.available("ospf"):
            self.missing("ospf", "FG-ENC-006", "Medium", "OSPF authentication can be validated")
        else:
            ospf = self.value("ospf")
            ospf_objects = rows(ospf)
            blob = json.dumps(ospf).lower() if ospf is not None else ""
            configured = bool(ospf_objects) and bool(blob.strip("{}[] \n"))
            authentication = [norm(value) for value in recursive_values(ospf, {"authentication", "auth-mode", "authentication-type"})]
            authenticated = any(value in {"md5", "message-digest"} for value in authentication) or "message-digest" in blob
            self.boolean(True if not configured else authenticated, "FG-ENC-006", "Medium", "OSPF uses message-digest authentication or is not configured",
                         "OSPF configured" if configured else "OSPF not configured", "Enable OSPF message-digest authentication.")

    def check_dos(self):
        if not self.available("dos"):
            self.missing("dos", "FG-DOS-001", "Medium", "DoS policy posture can be validated")
            return
        policies = [policy for policy in rows(self.value("dos")) if active(policy)]
        self.boolean(bool(policies), "FG-DOS-001", "Medium", "Active DoS policies are configured",
                     f"active count={len(policies)}", "Create and tune DoS policies for exposed interfaces.")
        records = {}
        for policy in policies:
            for obj in walk_dicts(policy):
                anomaly = norm(field(obj, "name", "anomaly", "type"))
                if anomaly in DOS_ANOMALIES and active(obj):
                    records.setdefault(anomaly, []).append(obj)
        for anomaly in DOS_ANOMALIES:
            found = records.get(anomaly, [])
            self.boolean(bool(found), f"FG-DOS-{anomaly}", "Medium", f"DoS anomaly {anomaly} is enabled",
                         f"enabled instances={len(found)}", f"Enable and tune {anomaly} where applicable.")
        all_records = [item for values in records.values() for item in values]
        log_values = [field(item, "log", "logtraffic") for item in all_records]
        log_result = None if not all_records or any(value is None for value in log_values) else all(enabled(value) for value in log_values)
        self.boolean(log_result, "FG-DOS-LOG", "Medium", "Recommended DoS anomalies have logging enabled",
                     log_values or "no enabled recommended anomalies", "Enable anomaly logging, observe normal traffic, and tune thresholds.")

    def check_policies(self):
        if not self.available("policies"):
            self.missing("policies", "API-POLICIES", "Medium", "Firewall-policy hygiene can be validated")
            return
        policies = [policy for policy in rows(self.value("policies")) if active(policy)]
        if not policies:
            self.boolean(None, "FG-POL-006", "Medium", "Broad services have documented justification",
                         "No active policies returned", "Review API scope and firewall policy design.")
            self.boolean(None, "FG-LOG-004", "Medium", "Required firewall-policy traffic is logged",
                         "No active policies returned", "Review logging requirements.")
            return
        broad = [name(policy) for policy in policies if any(norm(value) in {"all", "any"} for value in named_values(field(policy, "service")))]
        no_log = [name(policy) for policy in policies if disabled(field(policy, "logtraffic", default="disable"))]
        self.boolean(True if not broad else None, "FG-POL-006", "Medium", "Broad services have documented justification",
                     broad or "none", "Review every ALL/ANY service and document approved exceptions.")
        self.boolean(not no_log, "FG-LOG-004", "Medium", "Required firewall-policy traffic is logged",
                     no_log or "none", "Enable traffic logging where operational visibility is required.")

    def check_vpn(self):
        if not self.available("ssl_vpn"):
            self.missing("ssl_vpn", "FG-VPN-005", "High", "SSL VPN TLS posture can be validated")
        else:
            settings = rows(self.value("ssl_vpn"))
            if not settings:
                self.boolean(True, "FG-VPN-000", "Info", "SSL VPN is not configured", "No SSL VPN settings", "")
            else:
                status = field(settings[0], "status")
                if status is None:
                    self.boolean(None, "FG-VPN-005", "High", "SSL VPN requires TLS 1.2 or newer",
                                 "SSL VPN status not returned", "Verify whether SSL VPN is enabled and its minimum TLS version.")
                elif disabled(status):
                    self.boolean(True, "FG-VPN-000", "Info", "SSL VPN is disabled", f"status={status}", "")
                else:
                    minimum = norm(field(settings[0], "ssl-min-proto-ver", "ssl-min-proto-version"))
                    result = None if not minimum else minimum not in {"tls1-0", "tls1-1", "tls1.0", "tls1.1"}
                    self.boolean(result, "FG-VPN-005", "High", "SSL VPN requires TLS 1.2 or newer",
                                 f"minimum={minimum or 'not returned'}", "Require TLS 1.2 or later.")

        if not self.available("ipsec"):
            self.missing("ipsec", "FG-VPN-007", "High", "IPsec cryptography can be validated")
            return
        phase1 = [item for item in rows(self.value("ipsec")) if active(item)]
        if not phase1:
            self.boolean(True, "FG-VPN-000-IPSEC", "Info", "IPsec is not configured", "No active phase1 interfaces", "")
            return
        ikev1, legacy = [], []
        for item in phase1:
            if str(field(item, "ike-version", default="")) == "1":
                ikev1.append(name(item))
            proposal = norm(field(item, "proposal"))
            groups = re.split(r"[ ,]+", norm(field(item, "dhgrp")))
            if any(token in proposal for token in ("3des", "des", "md5")) or any(group in {"1", "2", "5"} for group in groups):
                legacy.append(name(item))
        self.boolean(not ikev1, "FG-VPN-006", "Medium", "IPsec prefers IKEv2", ikev1 or "none", "Prefer IKEv2 where peers support it.")
        self.boolean(not legacy, "FG-VPN-007", "High", "IPsec avoids legacy cryptography", legacy or "none", "Remove DES, 3DES, MD5, and weak DH groups.")

    def check_fortiguard(self):
        if not self.available("license"):
            self.missing("license", "FG-FGD-001", "High", "FortiGuard/license status can be validated")
        else:
            payload = self.value("license")
            statuses = [norm(value) for value in recursive_values(payload, {"status", "state", "license_status"})]
            bad = [value for value in statuses if value in {"expired", "invalid", "unlicensed", "disconnected", "error", "failed"}]
            good = [value for value in statuses if value in {"valid", "licensed", "registered", "connected", "active"}]
            result = False if bad else True if good else None
            self.boolean(result, "FG-FGD-001", "High", "FortiGuard/license status contains no explicit failure",
                         f"good={good}; bad={bad}; observed={statuses[:20]}", "Verify contracts and FortiGuard connectivity.")
        self.manual("FG-FGD-002", "High", "AV, IPS, and antispam databases are current",
                    "Verify database versions and update timestamps; configure alerts for stale databases.")

    def add_manual_controls(self):
        self.manual("FG-PHYS-001", "High", "The appliance is physically secured and port security is appropriate",
                    "Validate physical controls and use 802.1X where unauthorized devices could connect.")
        self.manual("FG-PSIRT-001", "High", "A Fortinet PSIRT monitoring and remediation process exists",
                    "Review applicable advisories and document remediation or compensating controls.")
        self.manual("FG-PEN-001", "Medium", "Authorized penetration testing is performed",
                    "Review recent test scope, findings, remediation, and retest evidence.")
        self.manual("FG-BACKUP-001", "High", "Configuration backups are encrypted, protected, retained, and tested",
                    "Verify encryption, password masking for third parties, secure storage, retention, deletion, and restoration tests.")
        self.manual("FG-REG-001", "Low", "The FortiGate is registered with active support",
                    "Confirm Fortinet registration and support entitlement.")

    def save(self):
        Path(self.args.evidence).write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        counts = {status: sum(item["status"] == status for item in self.results) for status in ("PASS", "FAIL", "REVIEW")}
        baseline = BASELINES[self.args.baseline]
        lines = [
            "FortiGate REST API Hardening Posture Report",
            f"Generated: {dt.datetime.now().astimezone().isoformat()}",
            f"Target: {self.args.host}:{self.args.port}",
            f"VDOM: {self.args.vdom}",
            f"Selected baseline: {baseline['label']}",
            f"Baseline source: {baseline['url']}",
            f"Summary: PASS={counts['PASS']} FAIL={counts['FAIL']} REVIEW={counts['REVIEW']}",
            "",
        ]
        for result in self.results:
            lines.extend([
                f"{result['status']:<7} {result['control_id']:<24} {result['severity']:<8} {result['description']}",
                f"        Evidence: {result['evidence']}",
                f"        Recommendation: {result['recommendation']}",
                "",
            ])
        lines.append("REVIEW means the API data was insufficient, the recommendation is contextual, or external evidence is required.")
        Path(self.args.report).write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--vdom", default="root")
    parser.add_argument("--baseline", choices=tuple(BASELINES), default="7.4")
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--verify-tls", dest="verify_tls", action="store_true")
    parser.add_argument("--no-verify-tls", dest="verify_tls", action="store_false")
    parser.set_defaults(verify_tls=False)
    parser.add_argument("--report", required=True)
    parser.add_argument("--evidence", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ValueError("API token file is empty")
        scanner = Scanner(args, token)
        scanner.collect()
        if not any(item and item.get("ok") for item in scanner.data.values()):
            Path(args.evidence).write_text(json.dumps(scanner.data, indent=2), encoding="utf-8")
            statuses = {item.get("http_status") for item in scanner.data.values() if item}
            if 401 in statuses:
                message, rc = "FortiGate REST API authentication failed (HTTP 401): the API token was rejected.", 3
            elif 403 in statuses:
                message, rc = "FortiGate REST API access denied (HTTP 403): verify API-profile permissions and trusted hosts.", 4
            else:
                errors = sorted({str(item.get("error")) for item in scanner.data.values() if item and item.get("error")})
                detail = "; ".join(errors[:3]) or "no endpoint returned data"
                message, rc = f"FortiGate REST API scan failed: {detail}.", 2
            Path(args.report).write_text(message + "\n", encoding="utf-8")
            return rc
        scanner.run_checks()
        scanner.save()
        return 0
    except Exception as exc:
        Path(args.report).write_text(f"FortiGate REST API scan failed: {exc}\n", encoding="utf-8")
        return 1


if __name__ == "__main__":
    sys.exit(main())
