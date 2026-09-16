# MCP Abilities - Wordfence

Let your AI assistant investigate a WordPress login problem, follow a security scan and review suspicious traffic using the Wordfence data already on your site. When you choose a response, the assistant can release a lockout, add or remove an IP block, or add a specific address to Wordfence's allowlist.

[![Release](https://img.shields.io/badge/release-1.0.18-blue)](https://downloads.devenia.com/mcp-abilities-wordfence.zip)
[![License](https://img.shields.io/badge/license-GPLv2%2B-blue)](https://www.gnu.org/licenses/gpl-2.0.html)
[![WordPress](https://img.shields.io/badge/WordPress-6.9%2B-blue)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple)](https://www.php.net/)

**Tested up to:** 7.1

**Stable tag:** 1.0.18

**License:** GPLv2 or later

**Tags:** security, wordfence, mcp, api, automation

## What It Does

An editor cannot sign in. Your assistant can inspect the login lockout list, read the reason and help identify the exact address. If you decide to release that lockout, it can perform the change and read the result back. The editor still needs to complete the normal login.

The same connection supports other recurring jobs:

- Follow a requested scan through its status and findings, then prepare a list of issues for review.
- Compare a reported problem with recent traffic events, including the request path, response status and recorded action.
- Review IP restrictions and their expiry before adding a block or removing a selected restriction.
- Add an explicitly selected address to the native allowlist when a continuing security exception is justified.

The add-on works through WordPress's authenticated Abilities API. Wordfence owns the firewall, scan engine, traffic records and access rules.

## The Real Workflow

1. Name the site and task: for example, investigate why an editor cannot sign in.
2. Have the assistant read the relevant records, including the address, event time and reason.
3. Choose the specific action supported by that evidence.
4. Let the assistant run it with an authorised WordPress account.
5. Read back the result and test the affected activity.

A request to start a scan is not a completed scan. If `verified` is false, the start request has not yet been confirmed by scan activity. Read the status again before drawing a conclusion.

## Why This Feels Different

You can move from a reported problem to the matching Wordfence record in the same conversation. The assistant can explain the evidence and carry out the selected action, instead of leaving you to find the relevant screen and copy an address between tools.

## Before vs After

| Task | Manual sequence | With the add-on |
| --- | --- | --- |
| Editor locked out | Find the address and reason, release the lockout, ask the editor to try again | Ask the assistant to inspect the record, perform the chosen release and check the remaining restrictions |
| Scan follow-up | Open the scan screen repeatedly and collect issue details | Ask for progress and a summary grounded in the returned findings |
| Suspicious activity | Compare traffic entries with the block list | Ask the assistant to gather both sets of evidence before choosing a response |

## Who It Is For

Site administrators and maintenance teams already using Wordfence who want an AI assistant to help with recurring investigation and access-management work. Each call operates on the connected WordPress installation; a multi-site maintenance client must select and authorise its connections separately.

## Requirements

- WordPress 6.9 or later, including the built-in Abilities API.
- PHP 8.0 or later.
- Active Wordfence Security and its configured scan/firewall features.
- WordPress MCP Adapter, MCP Expose Abilities and an authenticated MCP client.
- `manage_options` permission on a single site, or `manage_network` on WordPress Multisite, matching Wordfence's administration access.

Wordfence remains responsible for feature availability, licensing, scan scheduling and traffic retention. This add-on does not add premium Wordfence features.

## Documentation

- [Product page](https://devenia.com/plugins/mcp-abilities-wordfence/)
- [Base stack: MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
- [Wordfence blocking](https://www.wordfence.com/help/blocking/)
- [Wordfence developer API and IP allowlist](https://www.wordfence.com/help/advanced/wordfence-api/)

## Start Here

Install the requirements and discover the available abilities. Start with `wordfence/get-status` to confirm the connected site can read Wordfence. Then give the assistant one concrete task, such as: “Find the lockout for this editor's confirmed IP address and explain the recorded reason.”

## Abilities (11)

| Ability | What it does |
| --- | --- |
| `wordfence/get-status` | Read native firewall mode, scan state, open issue count, IP-block count and lockout count |
| `wordfence/get-scan-status` | Read current scan activity, recorded scan outcome and scheduling timestamps |
| `wordfence/start-scan` | Request a scan through the native engine and report whether activity confirms the start |
| `wordfence/list-blocked-ips` | List current IP restrictions, reasons and expiry, including rate restrictions |
| `wordfence/list-live-traffic` | Read recent stored traffic entries |
| `wordfence/block-ip` | Create a temporary or permanent IP block using native validation and readback |
| `wordfence/unblock-ip` | Remove a matching IP restriction and check whether another IP restriction remains |
| `wordfence/list-scan-issues` | Read new, ignored or all recorded scan findings |
| `wordfence/list-lockouts` | List current login lockouts and their reasons |
| `wordfence/unlock-ip` | Remove a matching login lockout and verify its removal |
| `wordfence/whitelist-ip` | Add one address to the native Wordfence allowlist and verify the stored entry |

Lists use `page` and `per_page` (default 50, maximum 200). Scan findings also accept `status`: `new`, `ignored` or `all`. Missing tables and failed database reads return `success: false`; they must not be interpreted as a clean report.

Scan timestamps are UTC. The legacy `last_scan_start` field records the last **scheduled** scan start, not every manual start. `last_scan_end` records a finished scan, which may have failed: read `last_scan_status`. The legacy `last_scheduled` field contains the **next** scheduled scan time.

## Usage Examples

### Inspect an editor's login lockout

```json
{
  "ability_name": "wordfence/list-lockouts",
  "parameters": {"page": 1, "per_page": 50}
}
```

Compare the returned address and event details with the editor's report. After choosing to release that specific restriction:

```json
{
  "ability_name": "wordfence/unlock-ip",
  "parameters": {"ip": "192.0.2.12"}
}
```

The address is a documentation example. Use the affected person's confirmed current address, then ask them to test the normal login.

### Review scan findings

```json
{
  "ability_name": "wordfence/list-scan-issues",
  "parameters": {"status": "new", "page": 1, "per_page": 50}
}
```

### Create a selected temporary block

```json
{
  "ability_name": "wordfence/block-ip",
  "parameters": {
    "ip": "192.0.2.13",
    "reason": "Repeated requests reviewed by the site administrator",
    "permanent": false
  }
}
```

Temporary blocks use Wordfence's configured duration. An existing block with a different duration is preserved and reported rather than silently reclassified.

## Safety and Ownership Boundaries

- Releasing a login lockout, removing an IP block and adding an allowlist entry have different effects. Other access restrictions can remain after one is removed.
- An IP allowlist entry is a broad security exception. Wordfence documents that traffic from the address bypasses its security checks, including two-factor authentication. It is not a routine substitute for releasing a lockout. [Wordfence API documentation](https://www.wordfence.com/help/advanced/wordfence-api/)
- A stored block is not proof of end-to-end enforcement. Test the relevant request or login after a change.
- Traffic reflects what Wordfence has stored under the site's logging settings. A scan finding needs investigation; the add-on does not repair files, patch vulnerabilities, dismiss findings or guarantee a clean site.
- Security data may contain IP addresses, request URLs and file paths. Give access only to clients that should see the connected site's security records.
- The add-on does not change Wordfence's firewall mode, passwords, scan schedule or individual firewall rules.

## Installation


For update notifications in WordPress, install [Devenia MCP Updater](https://downloads.devenia.com/devenia-mcp-updater.zip). The updater is optional. You choose which plugins update automatically through WordPress.

1. Install and configure Wordfence Security and the base MCP stack.
2. [Download the ZIP](https://downloads.devenia.com/mcp-abilities-wordfence.zip).
3. In WordPress, open **Plugins → Add New Plugin → Upload Plugin**, select the ZIP and activate it.
4. Discover the `wordfence/*` abilities through the authenticated client and read the status.

## Changelog


### 1.0.18

Add one dismissible Plugins-screen reminder when Devenia MCP Updater is missing or inactive, with persistent install or activate links. Automatic updates remain your choice in WordPress.

### 1.0.17

- Read firewall mode from Wordfence's native model instead of inferring it from bootstrap files.
- Honour freshly stored allowlist entries during subsequent operations in the same request.
- Verify IP-block, unblock, login-unlock and native allowlist results; preserve existing blocks with different durations.
- Report unavailable security data and failed reads explicitly.
- Require actual scan activity to verify a start and clarify timestamp meanings.
- Match Wordfence's network-administrator permission on Multisite and describe allowlisting's broader effect.

### 1.0.14

- Use the Wordfence scan engine entrypoint for scan requests.

## Contributing

Keep changes focused on the public abilities and native Wordfence behaviour. Include a reproducible case and relevant checks for bug fixes.

## License

GPLv2 or later. See the [GNU GPL v2 licence](https://www.gnu.org/licenses/gpl-2.0.html).

## Author

[basicus](https://profiles.wordpress.org/basicus/)

## Links

- [Product page](https://devenia.com/plugins/mcp-abilities-wordfence/)
- [Download](https://downloads.devenia.com/mcp-abilities-wordfence.zip)
- [Base stack](https://devenia.com/plugins/mcp-expose-abilities/)
