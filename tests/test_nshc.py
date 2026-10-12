import io
import json
import tarfile
import unittest
from pathlib import Path

import tempfile

from nshc.cli import scan_bundles, summary_text
from nshc.crypto import CryptoError, decrypt_bytes, encrypt_bytes
from nshc.evaluate import evaluate
from nshc.parse import parse_node
from nshc.bundle import CollectedNode, load_input
from nshc.catalog import CheckDef, risk_label
from nshc.redact import redact
from nshc.version import parse_version


def _check(check_id: str, platforms: list[str] | None = None) -> CheckDef:
    return CheckDef(
        id=check_id,
        platforms=platforms or ["VPX", "MPX", "SDX", "BLX"],
        focus="Test",
        title=check_id,
        details="",
        resources=[],
        likelihood=2,
        impact=3,
        wording="Do the secure thing.",
    )


SHOW = """
 Done
exec: show ns version
	NetScaler NS13.0: Build 90.7.nc, Date: Jan 1 2024, 00:00:00   (64-bit)
 Done
exec: show ns hardware
	Platform: Netscaler Virtual Appliance
 Done
exec: show ns feature
	Web Logging                    WL                   ON
	Surge Protection               SP                   OFF
	SSL VPN                        SSLVPN               ON
	AAA                            AAA                  ON
 Done
exec: show ns mode
	Layer 3 mode (ip forwarding)   L3                   ON
	Layer 2 mode                   L2                   OFF
	Edge configuration             Edge                 OFF
	MAC-based forwarding           MBF                  OFF
 Done
exec: show HA node
1)	Node ID:      0
	Fail-Safe Mode: OFF
 Done
exec: show ns ip 10.0.0.5
	IP: 10.0.0.5
	Type: NetScaler IP
	management access: Enabled
	telnet: Enabled
	ftp: Enabled
	gui: Enabled
	snmp: Enabled
	restrict access: Disabled
	ssh: Enabled
 Done
exec: show system parameter
	Timeout:  900
	Minpasswordlen:  1
	Strongpassword:  disabled
	ForcePasswordChange:  DISABLED
 Done
exec: show system user
1)	User name: nsroot
	External Authentication: ENABLED
	Timeout: 900
 Done
exec: show ssl profile
1)	Name: weak_fe 	(Front-End)
	SSLv3: DISABLED	TLSv1.0: ENABLED  TLSv1.1: ENABLED  TLSv1.2: ENABLED  TLSv1.3: DISABLED
	HSTS: DISABLED
 Done
exec: show ssl vserver
1) VServer Name: gw
	Profile Name :weak_fe
 Done
exec: show authentication samlAction
1)	Name: sp1
 Done
exec: show authentication samlIdPProfile
 Done
exec: show aaa parameter
	Login Encryption: DISABLED
	EnableEnhancedAuthFeedback: NO
 Done
exec: show vpn parameter
	Authorization action : ALLOW
 Done
exec: show configstatus
	Consistent: NO
 Done
exec: show ntp server
 Done
exec: show ntp sync
	NTP Status: DISABLED
 Done
"""

NSCONF = """#NS13.0 Build 90.7
set ns hostName lab
enable ns feature WL SSLVPN AAA
add authentication samlAction sp1
add authentication vserver aaa_vs SSL 10.1.1.1 443
set system user nsroot XXXXXXX -encrypted deadbeefdeadbeefdeadbeef
"""


class CryptoTests(unittest.TestCase):
    def test_roundtrip_and_wrong_passphrase(self):
        blob = encrypt_bytes(b"health-check", "correct horse battery")
        self.assertTrue(blob.startswith(b"NSHC1\n"))
        self.assertEqual(decrypt_bytes(blob, "correct horse battery"), b"health-check")
        with self.assertRaises(CryptoError):
            decrypt_bytes(blob, "wrong horse battery")

    def test_short_passphrase_rejected(self):
        with self.assertRaises(CryptoError):
            encrypt_bytes(b"x", "short")


class RedactTests(unittest.TestCase):
    def test_encrypted_flag_removed(self):
        cleaned = redact("set system user nsroot XXX -encrypted deadbeefdeadbeefdeadbeef")
        self.assertNotIn("deadbeefdeadbeefdeadbeef", cleaned)
        self.assertIn("[redacted]", cleaned)


class EngineTests(unittest.TestCase):
    def test_version_parse(self):
        version = parse_version("NetScaler NS14.1: Build 73.37.nc")
        self.assertIsNotNone(version)
        assert version is not None
        self.assertEqual(version.label, "14.1-73.37")

    def test_risk_matrix(self):
        self.assertEqual(risk_label(2, 3), "HIGH")
        self.assertEqual(risk_label(1, 1), "LOW")

    def test_summary_and_report_path_guard(self):
        text = summary_text(
            {
                "advisory_data": "2026-10-12",
                "appliances": [
                    {
                        "hostname": "lab",
                        "source": "lab",
                        "platform": "VPX",
                        "version": "14.1-73.37",
                        "counts": {"fail": 1, "review": 0, "pass": 0, "na": 0},
                        "findings": [
                            {"status": "fail", "risk": "HIGH", "id": "nshc000001", "title": "Upgrade firmware"},
                        ],
                    }
                ],
            }
        )
        self.assertIn("lab  VPX  14.1-73.37", text)
        self.assertIn("nshc000001", text)
        self.assertIn("2026-10-12", text)
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "support.tgz"
            bundle.write_bytes(b"not-a-bundle")
            with self.assertRaises(ValueError):
                scan_bundles([bundle], bundle, passphrase="correct horse battery")

    def test_synthetic_findings(self):
        node = CollectedNode(
            name="lab",
            files={"nsconfig/ns.conf": NSCONF, "shell/showcmds.txt": SHOW},
        )
        app = parse_node(node)
        wanted = [
            "nshc000001",
            "nshc000002",
            "nshc000008",
            "nshc000023",
            "nshc000027",
            "nshc000033",
            "nshc000048",
            "nshc000055",
            "nshc002003",
            "nshc003001",
        ]
        outcomes = {item.id: item for item in evaluate(app, [_check(item) for item in wanted])}
        for check_id in wanted:
            self.assertEqual(outcomes[check_id].status, "fail", check_id)
        blob = json.dumps([item.evidence for item in outcomes.values()])
        self.assertNotIn("deadbeefdeadbeefdeadbeef", blob)

    def test_syslog_transport_and_rpc_secure(self):
        show = """exec: show HA node
	Node ID: 0
	Node ID: 1
 Done
exec: show ns rpcNode
	Secure: OFF
	ValidateCert: NO
 Done
exec: show gslb site
	1) SiteName: a
 Done
"""
        nsconf = """add audit syslogAction localudp 10.0.0.5 -logLevel ALL
add audit syslogAction viatcp 10.0.0.6 -transport TCP -logLevel ALL
add audit syslogAction viatls 10.0.0.7 -transport SSL -logLevel ALL
"""
        app = parse_node(CollectedNode(name="lab", files={"nsconfig/ns.conf": nsconf, "shell/showcmds.txt": show}))
        self.assertEqual((app.syslog_udp, app.syslog_tcp, app.syslog_tls), (1, 1, 1))
        extras = {item.id: item for item in evaluate(app, [])}
        self.assertEqual(extras["nshc-x-syslog-transport"].status, "review")
        self.assertEqual(extras["nshc-x-rpc-secure"].status, "fail")
        evidence = json.dumps([item.evidence for item in extras.values()])
        self.assertNotIn("10.0.0.5", evidence)

    def test_cleanup_and_routing(self):
        show = """
exec: show route
	Network          Netmask          Gateway/OwnedIP  VLAN    State   Traffic Domain  Type
1)	10.0.0.0         255.255.255.0    10.0.0.10     0       UP      0              DIRECT
2)	172.16.0.0       255.255.0.0      10.9.1.1      0       UP      0              STATIC
3)	192.0.2.0        255.255.255.0    10.0.0.10     0       DOWN    0              STATIC
exec: show service
1)	good_svc (10.0.0.20:80) - HTTP
	State: UP
	Server Name: good
2)	orphan_svc (10.0.0.20:81) - HTTP
	State: DOWN
	Server Name: good
exec: show lb vserver
1)	vs1 (10.0.0.30:80) - HTTP
	State: UP
	No. of Bound Services :  1 (Total) 	 1 (Active)
2)	empty (10.0.0.31:80) - HTTP
	State: UP
	No. of Bound Services :  0 (Total) 	 0 (Active)
exec: show cs vserver
1)	apps (10.0.0.40:443) - SSL
	State: UP
exec: show gslb vserver
1)	lonely - HTTP
	State: DOWN
	No. of Bound Services :  0 (Total) 	 0 (Active)
exec: show ns pbr
1)	Name: OLD
	Hits: 0
	Active Status: ENABLED
	Applied Status: NOTAPPLIED
	NextHop: 10.0.0.1
2)	Name: BADHOP
	Hits: 3
	Active Status: ENABLED
	Applied Status: APPLIED
	NextHop: 198.51.100.1
"""
        nsconf = """
add server good 10.0.0.20
add server far 10.8.8.8
add server spare 10.0.0.50
add service good_svc good HTTP 80
add service orphan_svc good HTTP 81
add service far_svc far HTTP 80
add service adm_metric_collector_svc_1 10.0.0.9 HTTP 5563
add lb vserver vs1 HTTP 10.0.0.30 80
add lb vserver empty HTTP 10.0.0.31 80
add lb vserver cs_target HTTP 10.0.0.32 0
add cs vserver apps SSL 10.0.0.40 443
add cs action act -targetLBVserver cs_target
bind cs vserver apps -policyName pol -priority 10
add gslb vserver lonely HTTP
bind lb vserver vs1 good_svc
add lb monitor custom_mon HTTP
disable lb vserver empty
"""
        app = parse_node(CollectedNode(name="lab", files={"nsconfig/ns.conf": nsconf, "shell/showcmds.txt": show}))
        extras = {item.id: item for item in evaluate(app, [])}
        cleanup = " ".join(extras["nshc-x-unused"].evidence)
        routing = " ".join(extras["nshc-x-route"].evidence)
        self.assertEqual(extras["nshc-x-unused"].status, "review")
        self.assertEqual(extras["nshc-x-route"].status, "fail")
        for name in ("orphan_svc", "adm_metric_collector_svc_1", "lonely", "empty", "spare", "custom_mon"):
            self.assertIn(name, cleanup)
        self.assertNotIn("good_svc", cleanup)
        idle = next(line for line in extras["nshc-x-unused"].evidence if line.startswith("Virtual servers with no services"))
        self.assertIn("lonely", idle)
        self.assertNotIn("cs_target", idle)
        pointed = next(line for line in extras["nshc-x-unused"].evidence if line.startswith("Content switching"))
        self.assertIn("cs_target", pointed)
        self.assertIn("10.9.1.1", routing)
        self.assertIn("192.0.2.0", routing)
        self.assertIn("10.8.8.8", routing)
        self.assertIn("BADHOP", routing)
        self.assertIn("OLD", routing)

    def test_partial_target_and_new_checks(self):
        from nshc.identify import apply_identifiers, mask_ipv4

        self.assertEqual(mask_ipv4("gateway 10.20.30.40"), "gateway x.x.30.40")
        show = """
exec: show route
1)	10.0.0.0         255.255.255.0    10.0.0.1      0       UP      0              DIRECT
exec: show route6
1)	::1/128  ::1  1  PA  0
exec: show ssl vserver
	VServer Name: apps
	Profile Name: weak_prof
exec: show ssl profile
1)	Name: weak_prof 	(Front-End)
	Deny SSL Renegotiation		NO
exec: show ns httpProfile
1)	Name: nshttp_default_profile
	Drop invalid HTTP requests: DISABLED
	Mark HTTP/0.9 requests as invalid: DISABLED
	Mark CONNECT requests as invalid: DISABLED
	Drop extra CRLF: ENABLED
"""
        nsconf = """
add lb vserver apps HTTP 10.50.8.20 80
bind ssl profile weak_prof -eccCurveName P_224
bind ssl profile weak_prof -eccCurveName P_256
"""
        app = parse_node(CollectedNode(name="lab", files={"nsconfig/ns.conf": nsconf, "shell/showcmds.txt": show}))
        outcomes = {item.id: item for item in evaluate(app, [_check(i) for i in ("nshc000078", "nshc000079", "nshc000080", "nshc000081", "nshc000082", "nshc000083")])}
        self.assertEqual(outcomes["nshc000078"].status, "fail")
        self.assertEqual(outcomes["nshc000079"].status, "fail")
        self.assertEqual(outcomes["nshc000080"].status, "fail")
        self.assertEqual(outcomes["nshc000081"].status, "fail")
        self.assertEqual(outcomes["nshc000082"].status, "na")
        self.assertEqual(outcomes["nshc000083"].status, "pass")
        tagged = apply_identifiers(app, [outcomes["nshc000079"]])[0]
        blob = " ".join(tagged.evidence)
        self.assertIn("VIP apps (x.x.8.20:80)", blob)
        self.assertNotIn("10.50.8.20", blob)

    def test_tar_skips_traversal_and_keys(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            payload = NSCONF.encode()
            info = tarfile.TarInfo("collector/nsconfig/ns.conf")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
            show = b" Done\nexec: show ns version\n\tNetScaler NS14.1: Build 73.46.nc\n Done\n"
            info = tarfile.TarInfo("collector/shell/showcmds.txt")
            info.size = len(show)
            archive.addfile(info, io.BytesIO(show))
            key = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
            info = tarfile.TarInfo("collector/nsconfig/ssl/server.key")
            info.size = len(key)
            archive.addfile(info, io.BytesIO(key))
            evil = b"nope"
            info = tarfile.TarInfo("collector/../../windows/system32/evil.txt")
            info.size = len(evil)
            archive.addfile(info, io.BytesIO(evil))
        path = Path(__file__).with_name("_sample.tgz")
        path.write_bytes(buffer.getvalue())
        try:
            nodes = load_input(path)
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(len(nodes), 1)
        self.assertIn("server.key", nodes[0].skipped_keys)
        joined = " ".join(nodes[0].files)
        self.assertNotIn("evil.txt", joined)
        self.assertNotIn("BEGIN PRIVATE KEY", joined)

    def test_hardening_extras(self):
        show = """
exec: show ns param
	Cookie version: 0
	Persistence Cookie Secure Flag: DISABLED
	Timezone: GMT
 Done
exec: show aaa parameter
	HttpOnly Cookie: DISABLED
	CSP Header: DISABLED
 Done
exec: show ssl profile
1)	Name: fe_prof (FrontEnd)
	OCSP Stapling: DISABLED
	TLSv1.2: ENABLED
 Done
exec: show ssl certKey
1)	Name: app_cert
	Days to expiration: 10
	Certificate Expiry Monitor: DISABLED
	Public Key size: 2048
 Done
exec: show dns nameServer
1)	10.9.9.9 - State: DOWN Protocol: UDP
 Done
exec: show interface
1)	Interface 1/1 (NetScaler Virtual Interface) #0
	flags=0xe060 <ENABLED, UP, UP, 802.1q>
	MTU=1500, native vlan=1, MAC=00:11:22:33:44:55, uptime 1h
	RX: Pkts(10) Bytes(10) Errs(2) Drops(3) Stalls(0)
	TX: Pkts(10) Bytes(10) Errs(0) Drops(0) Stalls(0)
 Done
exec: show vlan
1)	VLAN ID: 1
	Interfaces : 1/1 1/2
 Done
exec: show ns httpProfile
1)	Name: nshttp_default_profile
	HTTP/2: DISABLED
	HTTP/3: DISABLED
	Drop invalid HTTP requests: ENABLED
	Mark HTTP/0.9 requests as invalid: ENABLED
	Mark CONNECT requests as invalid: ENABLED
	Drop extra CRLF: ENABLED
 Done
exec: show HA node
	Node ID: 0
	Node State: UP
 Done
exec: show ns rateControl
	TCP threshold: 0 per 10 ms
 Done
exec: show appfw profile
1)	Name: appfw_prof
	AddCookieFlags: none
	InsertCookieSamesiteAttribute: OFF
 Done
exec: show ns capacity
	Maximum Bandwidth             : 10000 Mbps
	Actual Bandwidth              : 9000 Mbps
 Done
"""
        nsconf = """
add ns ip 10.0.0.5 255.255.255.0 -type NSIP
add route 0.0.0.0 0.0.0.0 10.0.0.1
add lb vserver apps HTTP 10.0.0.20 80
add vpn vserver gateway SSL 10.0.0.21 443
add authentication ldapAction ldap1
add lb monitor custom_mon HTTP -interval 2 -downTime 5
bind ssl profile fe_prof -eccCurveName P_256
"""
        app = parse_node(CollectedNode(name="lab", files={"nsconfig/ns.conf": nsconf, "shell/showcmds.txt": show}))
        extras = {item.id: item for item in evaluate(app, [])}
        expected = {
            "nshc-x-headers": "review",
            "nshc-x-cookies": "review",
            "nshc-x-https-redirect": "fail",
            "nshc-x-ocsp": "fail",
            "nshc-x-mfa": "fail",
            "nshc-x-mgmt-exposure": "review",
            "nshc-x-cert-monitor": "review",
            "nshc-x-rate-limit": "review",
            "nshc-x-vmac": "na",
            "nshc-x-default-net": "review",
            "nshc-x-ha-sync": "na",
            "nshc-x-if-errors": "review",
            "nshc-x-vlan": "review",
            "nshc-x-backup": "review",
            "nshc-x-dns": "fail",
            "nshc-x-timezone": "pass",
            "nshc-x-license": "review",
            "nshc-x-ppe": "review",
            "nshc-x-cores": "review",
            "nshc-x-monitors": "review",
            "nshc-x-appflow": "review",
            "nshc-x-http2": "review",
            "nshc-x-audit-hash": "review",
            "nshc-x-pq": "review",
        }
        for check_id, status in expected.items():
            self.assertEqual(extras[check_id].status, status, check_id)
        quiet = []
        for check_id in ("nshc-x-mgmt-exposure", "nshc-x-default-net", "nshc-x-dns", "nshc-x-mfa"):
            quiet.extend(extras[check_id].evidence)
        blob = json.dumps(quiet)
        self.assertNotIn("10.0.0.5", blob)
        self.assertNotIn("10.0.0.1", blob)
        self.assertNotIn("10.9.9.9", blob)


if __name__ == "__main__":
    unittest.main()
