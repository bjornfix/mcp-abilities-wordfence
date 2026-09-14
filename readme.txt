=== MCP Abilities - Wordfence ===
Contributors: basicus
Tags: security, wordfence, mcp, api, automation
Requires at least: 6.9
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.0.16
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let an AI assistant investigate login lockouts, follow scans and review Wordfence traffic, then perform a selected IP or lockout action.

== Description ==

An editor cannot sign in. Your assistant can find the matching Wordfence lockout, explain the reason and release that specific restriction when you choose. It can also follow a scan through its status and findings, read recent traffic and manage selected IP restrictions.

Wordfence owns the scan engine, firewall and security records. This add-on connects its supported functions to WordPress's authenticated Abilities API.

= Requirements =

* WordPress 6.9 or later with its built-in Abilities API; PHP 8.0 or later.
* Active Wordfence Security, WordPress MCP Adapter and [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/).
* An authenticated MCP client with manage_options permission, or manage_network on WordPress Multisite.

= Abilities Included =

* wordfence/get-status: native firewall mode, scan state and security counts.
* wordfence/get-scan-status: scan activity, outcome and scheduling timestamps.
* wordfence/start-scan: request a native scan and report whether its start is verified.
* wordfence/list-blocked-ips: current IP restrictions, reasons and expiry.
* wordfence/list-live-traffic: recent stored traffic entries.
* wordfence/block-ip: a selected temporary or permanent native IP block.
* wordfence/unblock-ip: remove a matching IP restriction and check remaining blocks.
* wordfence/list-scan-issues: new, ignored or all recorded scan findings.
* wordfence/list-lockouts: current login lockouts and reasons.
* wordfence/unlock-ip: remove and verify a selected login lockout.
* wordfence/whitelist-ip: add and verify one native IP allowlist entry.

= Put it to work =

Ask the assistant to inspect an editor's confirmed IP address, follow a scan and summarise its findings, or compare suspicious traffic with existing blocks. Select a response after reviewing the evidence, then read back the result and test the affected activity.

Lists use page and per_page, with a default of 50 and maximum of 200. Missing tables and failed reads report failure rather than a clean report. A requested scan is not a completed scan. Scan timestamps use UTC; last_scan_start means the last scheduled start, last_scan_end can include failure, and last_scheduled means the next scheduled scan.

Releasing a login lockout does not reset a password or remove every access restriction. An allowlist entry is broader: Wordfence documents that traffic from the address bypasses its security checks, including two-factor authentication. Review that exception separately. The add-on does not repair scan findings, change firewall mode or provide continuous monitoring by itself.

Read the [product page](https://devenia.com/plugins/mcp-abilities-wordfence/) and [Wordfence API documentation](https://www.wordfence.com/help/advanced/wordfence-api/).

== Installation ==

1. Install and configure Wordfence Security and the base MCP stack.
2. Upload and activate mcp-abilities-wordfence through Plugins in WordPress.
3. Discover the wordfence abilities in the authenticated client.
4. Read the status before selecting a task.

== Changelog ==

= 1.0.16 =
* Read firewall mode from the native Wordfence model.
* Verify block, unblock, unlock and allowlist results and preserve existing blocks with different durations.
* Report missing security data and failed database reads explicitly.
* Require scan activity to verify a start and clarify timestamp meanings.
* Match native network-administrator permissions on Multisite and explain the scope of IP allowlisting.

= 1.0.14 =
* Fixed: `wordfence/start-scan` now uses the current Wordfence 8.x scan engine entrypoint while preserving compatibility with older supported entrypoints.
