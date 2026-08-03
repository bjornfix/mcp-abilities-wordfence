=== MCP Abilities - Wordfence ===
Contributors: basicus
Tags: security, wordfence, mcp, api, automation
Requires at least: 6.9
Tested up to: 7.0
Requires PHP: 8.0
Stable tag: 1.0.14
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

= 1.0.14 =
* Fixed: `wordfence/start-scan` now uses the current Wordfence 8.x scan engine entrypoint while preserving compatibility with older supported entrypoints.

= 1.0.13 =
* Updated: Declared compatibility with WordPress 7.0 for current plugin-check requirements.

= 1.0.12 =
* Fixed: `wordfence/list-live-traffic` now queries the real Wordfence `wfhits` schema on current Wordfence versions
* Fixed: live traffic results now return real rows instead of an empty array when the table exists

= 1.0.11 =
* Fixed: `wordfence/get-status` and `wordfence/get-scan-status` now use Wordfence's real scan time/state fields instead of treating `lastScanCompleted` as a timestamp
* Fixed: `wordfence/get-status` now counts issues directly from the Wordfence issues table
* Improved: `wordfence/start-scan` now verifies starts using Wordfence monitor timestamps

= 1.0.10 =
* Fixed: resolved Wordfence table names via Wordfence DB helpers so lowercase-table installs work correctly for live traffic and scan issues

= 1.0.9 =
* Fixed: `wordfence/list-live-traffic` now degrades cleanly to an empty result when the live-traffic table is unavailable on a site
* Fixed: `wordfence/list-scan-issues` now degrades cleanly to an empty result when the issues table is unavailable on a site

= 1.0.8 =
* Fixed: `wordfence/get-status` now derives firewall mode from actual WAF bootstrap state when config-only status is misleading
* Fixed: `wordfence/get-status` now reports completed scan time instead of scheduled scan time
* Fixed: `wordfence/get-status` now counts blocked IPs and lockouts via Wordfence APIs instead of raw table counts
* Fixed: `wordfence/start-scan` now reports whether the scan start was verified instead of always claiming success

= 1.0.7 =
* Fixed: Removed hard plugin header dependency on abilities-api to avoid slug-mismatch activation blocking


= 1.0.6 =
* Fixed: `wordfence/get-status` callback now accepts null input from proxy adapters

= 1.0.5 =
* Fixed: no-input abilities now accept `null` input for proxy adapters that drop empty objects
* Fixed: added optional no-op input key (`_`) for proxy adapters that require non-empty objects

= 1.0.4 =
* Fixed: Compatibility for no-input abilities in proxy stacks that pass empty objects as arrays
* Fixed: Clarified inactive plugin message (`Wordfence plugin is not active.`)

= 1.0.3 =
* Simplify active checks and cache table existence per request

= 1.0.2 =
* Improved: Database queries now use esc_sql() and proper $wpdb->prepare() for WordPress.org compliance
* Improved: Added phpcs:ignore comments for justified direct database queries to Wordfence tables

= 1.0.1 =
* Fixed: Updated to use Wordfence 8.x wfBlock API instead of deprecated methods

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
