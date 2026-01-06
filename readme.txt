=== MCP Abilities - Wordfence ===
Contributors: devenia
Tags: security, wordfence, mcp, api, automation
Requires at least: 6.9
Tested up to: 6.9
Requires PHP: 8.0
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Wordfence security abilities for MCP. Monitor security status, manage blocked IPs, view scan issues, and control lockouts via the Abilities API.

== Description ==

This add-on plugin extends [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/) with Wordfence security functionality. It enables AI agents and automation tools to monitor and manage WordPress security.

= Requirements =

* [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities) (core plugin)
* [Wordfence Security](https://wordpress.org/plugins/wordfence/) plugin

= Abilities Included =

**wordfence/get-status** - Get overall security status including firewall mode, last scan time, issues count, blocked IPs count, and lockouts count.

**wordfence/list-blocked-ips** - List all currently blocked IP addresses with reason and expiration info.

**wordfence/block-ip** - Block an IP address temporarily or permanently.

**wordfence/unblock-ip** - Remove an IP address from the block list.

**wordfence/list-scan-issues** - List security issues found by Wordfence scans with severity and details.

**wordfence/list-lockouts** - List IP addresses currently locked out due to failed login attempts.

**wordfence/unlock-ip** - Remove an IP from the lockout list.

**wordfence/whitelist-ip** - Add an IP to the allowlist so it will never be blocked.

= Use Cases =

* Monitor security status across multiple sites
* Automate IP blocking in response to threats
* Review scan issues via automation
* Manage lockouts without accessing wp-admin
* Enable AI agents to respond to security events

== Installation ==

1. Install and activate [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities)
2. Install and activate [Wordfence Security](https://wordpress.org/plugins/wordfence/)
3. Upload `mcp-abilities-wordfence` to `/wp-content/plugins/`
4. Activate through the 'Plugins' menu
5. The abilities are now available via the MCP endpoint

== Changelog ==

= 1.0.0 =
* Initial release
* Added wordfence/get-status ability
* Added wordfence/list-blocked-ips ability
* Added wordfence/block-ip ability
* Added wordfence/unblock-ip ability
* Added wordfence/list-scan-issues ability
* Added wordfence/list-lockouts ability
* Added wordfence/unlock-ip ability
* Added wordfence/whitelist-ip ability
