## Confirmed CVE-associated bugs 

The following are CVE bugs found with the help of this tool (some are still in embargo and will be added at a later date)

| Launchpad bug | Project        | CVE                | OSSA / OSSN                  | Brief summary                                                                                                                                                                                                                                                      |
| ------------: | -------------- | ------------------ | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
|   **2149775** | Keystone       | **CVE-2026-43001** | **OSSA-2026-015**            | Application credentials scoped to one project could create EC2 credentials for a different project. The official OSSA credits Tim Shephard for CVE-2026-43001 and references Launchpad bug 2149775. ([security.openstack.org][1])                                  |
|   **2150132** | Neutron        | **CVE-2026-49299** | **OSSA-2026-016**            | Policy bypass in Neutron tagging allowed project readers to mutate network-resource tags despite reader-only permissions. The official advisory credits Tim Shephard and links Launchpad bug 2150132. ([security.openstack.org][2])                                |
|   **2152115** | Neutron        | **CVE-2026-50266** | **OSSA-2026-021**            | Port RBAC [role-based access control] policy bypass allowed project managers to assign trusted `device_owner` values on shared networks. The advisory credits Tim Shephard and links Launchpad bug 2152115. ([security.openstack.org][3])                          |
|   **2150261** | Swift          | **CVE-2026-50221** | **OSSA-2026-024**            | Swift proxy-server SSRF [server-side request forgery] via header injection, allowing an unauthenticated attacker to trigger unauthorized requests from the proxy. The advisory credits Tim Shephard and links Launchpad bug 2150261. ([security.openstack.org][4]) |
|   **2150316** | oslo.messaging | **CVE-2026-44393** | **OSSN-0096**, no OSSA found | RabbitMQ TLS [Transport Layer Security] connections did not verify broker hostnames, creating MITM [man-in-the-middle] risk. The OpenStack OSSN credits Tim Shephard and links Launchpad bug 2150316. ([wiki.openstack.org][5])                                    |
|   **2152240** | Horizon        | **CVE-2026-55748** | **OSSN-0097**, no OSSA found | Horizon RC file generation failed to escape special characters in project names, allowing command execution when the generated RC file was sourced. The OpenStack OSSN credits Tim Shephard and links Launchpad bug 2152240. ([wiki.openstack.org][6])             |

## Confirmed OSSA-associated bugs without a standalone CVE

| Launchpad bug | Project  | OSSA              | Brief summary                                                                                                                                                                                                                                                                                                                              |
| ------------: | -------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
|   **2149789** | Keystone | **OSSA-2026-015** | Trust-scoped token issue related to credentials outside the delegated project. Tim’s own oss-security message lists bug 2149789 among the bugs he reported, and OSSA-2026-015 includes it among referenced Launchpad bugs. I found it associated with the Keystone advisory set, but not as a separate standalone CVE. ([openwall.com][7]) |


[1]: https://security.openstack.org/ossa/OSSA-2026-015.html "OSSA-2026-015: Multiple credential delegation and authorization bypass vulnerabilities in Keystone — OpenStack Security Advisories 0.0.1.dev348 documentation"
[2]: https://security.openstack.org/ossa/OSSA-2026-016.html "OSSA-2026-016: Neutron tagging policy bypass allows project readers to mutate tags — OpenStack Security Advisories 0.0.1.dev348 documentation"
[3]: https://security.openstack.org/ossa/OSSA-2026-021.html "OSSA-2026-021: Neutron port RBAC policy bypass allows project managers to set trusted device owners on shared networks — OpenStack Security Advisories 0.0.1.dev348 documentation"
[4]: https://security.openstack.org/ossa/OSSA-2026-024.html "OSSA-2026-024: Swift proxy-server SSRF via header injection — OpenStack Security Advisories 0.0.1.dev348 documentation"
[5]: https://wiki.openstack.org/wiki/OSSN/OSSN-0096?utm_source=chatgpt.com "OSSN/OSSN-0096"
[6]: https://wiki.openstack.org/wiki/OSSN/OSSN-0097?utm_source=chatgpt.com "OSSN/OSSN-0097"
[7]: https://www.openwall.com/lists/oss-security/2026/05/16/1?utm_source=chatgpt.com "oss-security - Sv: Coordinated Disclosure in the LLM Age"
