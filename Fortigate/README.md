# FortiGate Hardening Check (REST API)

This Shark Jack Display payload connects to an authorized FortiGate through the FortiOS REST API and produces a PASS/FAIL/REVIEW hardening report using read-only `GET` requests.

The control set is adapted from [PinePad79/fortigate_hardening_check](https://github.com/PinePad79/fortigate_hardening_check). No configuration-changing API methods are used.

## Project files

- `payload.txt`: Shark Jack Display payload, menus, status messages, and Cloud C² upload workflow
- `fortigate_check.py`: FortiOS REST API scanner and report generator
- `test_fortigate_check.py`: local regression tests for the hardening evaluations

## Install on Shark Jack Display

From the repository root, enter the Fortigate project directory and copy the runtime files into the active payload directory:

```sh
cd Fortigate
scp payload.txt fortigate_check.py root@172.16.24.1:/root/payload/
ssh root@172.16.24.1 'chmod 700 /root/payload/payload.txt /root/payload/fortigate_check.py'
```

The payload requires Python 3. Confirm it is available before running:

```sh
ssh root@172.16.24.1 'python3 --version'
```

## Requirements

- A FortiGate you own or are explicitly authorized to assess
- Network reachability from the Shark Jack to the FortiGate HTTPS/API service
- Python 3 on the Shark Jack; the scanner uses only Python's standard library
- A dedicated REST API administrator with a read-only access profile
- A trusted-host restriction allowing only the Shark Jack or its management subnet

Do not use a `super_admin` API account. Give the scanner read access only to the configuration and monitoring endpoints it needs.

## API token

Place the token on the Shark Jack, not in this repository or `default.cfg`:

```sh
printf '%s' 'YOUR_FORTIGATE_API_TOKEN' > /root/fortigate_api.token
chmod 600 /root/fortigate_api.token
```

The token is read from `/root/fortigate_api.token` by default, sent in the `Authorization: Bearer` header, and never written into reports or evidence files.

## Configuration

Use the display menus to set the IPv4 target, FortiOS baseline, and TLS verification. Advanced options can be placed in the payload's `default.cfg`:

```ini
FGT_HOST=192.168.1.99
FGT_PORT=443
FGT_VDOM=root
FGT_BASELINE=7.4
VERIFY_TLS=false
API_TOKEN_FILE=/root/fortigate_api.token
API_TIMEOUT=15
C2_UPLOAD=true
C2_UPLOAD_EVIDENCE=false
```

Enable `VERIFY_TLS` for production use and install the necessary CA trust chain on the Shark Jack. Disabling verification is intended for controlled labs using a self-signed FortiGate certificate.

## Output

Results are stored under `/root/loot/fortigate_hardening/`:

- `*_report.txt`: readable summary and individual findings
- `*_evidence.json`: raw endpoint results and errors, without the API token

The directory and output files are restricted to root. Reports and API evidence can expose sensitive configuration details and should be handled accordingly.

## Hak5 Cloud C²

Provision the Shark Jack with the `device.config` downloaded for that device from your Cloud C² server:

```sh
scp device.config root@172.16.24.1:/etc/device.config
ssh root@172.16.24.1 'chmod 600 /etc/device.config'
```

With `C2_UPLOAD=true`, the payload calls `C2CONNECT` after a successful scan, writes a short summary to the device log, and uploads the customer-readable report using `C2EXFIL STRING`. The report remains stored locally whether the C² connection succeeds or fails.

Use **Cloud C2 Upload → Enable** on the display to override an older profile that has uploads disabled. Authentication and access failures (HTTP 401/403) produce a specific on-screen warning and a diagnostic report; when C² is enabled, that failure report is uploaded too.

The display asks for a short customer label after each successful scan. This label becomes part of the C² loot name; use letters, numbers, `_`, or `-`, and do not put confidential information in it.

Raw API evidence is substantially more sensitive and is **not uploaded by default**. Set `C2_UPLOAD_EVIDENCE=true` only when the customer has approved sharing the underlying configuration evidence and your Cloud C² access controls and retention policy are appropriate.

The API token and `device.config` are never uploaded by this payload and must not be committed to the payload repository.

## Checks

The payload assesses firmware-family alignment, strong cryptography, management exposure, administrator trusted hosts and MFA, API-account privilege, NTP synchronization and authentication, centralized logging, local-in policy restrictions and logging, the six Fortinet-recommended DoS anomalies, USB auto-install, SNMPv3, LDAPS, RADSEC, OSPF authentication, firewall-policy hygiene, SSL VPN TLS, IPsec/IKE cryptography, and explicit FortiGuard/license states.

The selected 7.4, 7.6, or 8.0 baseline is recorded with its official Fortinet source. Shared machine-checkable settings use the same rule where the three guides agree. Version-sensitive private-data-encryption guidance distinguishes 7.4, the 7.6.1 behavior change, and 8.0.

Recommendations that cannot be proven from the collected API configuration are included as `REVIEW` controls instead of being silently omitted. These include current patch and lifecycle status, PSIRT operations, encrypted backup handling and restore testing, physical security and 802.1X, penetration-testing evidence, support registration, and FortiGuard database currency.

FortiOS schemas and endpoint permissions vary across firmware, models, VDOM modes, and access profiles. Missing endpoints and missing fields are intentionally reported as `REVIEW`, never inferred as compliant. `REVIEW` can also mean that the recommendation is contextual or requires external evidence; it is not automatically a pass or failure. Validate findings before remediation.

Local regression tests can be run with:

```sh
python3 -m unittest test_fortigate_check.py -v
```

## License and commercial use

The source is publicly available for inspection, learning, testing, and non-commercial use. Commercial use, resale, paid assessment delivery, incorporation into a commercial product or service, and commercial redistribution require prior written permission from the copyright holder.

See [LICENSE.md](../LICENSE.md) for the complete terms. To request commercial permission, contact the repository owner through the GitHub profile or repository contact options.
