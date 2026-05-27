# MCP Abilities - Wordfence

Wordfence security abilities for WordPress via MCP.

[![GitHub release](https://img.shields.io/github/v/release/bjornfix/mcp-abilities-wordfence)](https://github.com/bjornfix/mcp-abilities-wordfence/releases)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)

**Tested up to:** 7.0
**Stable tag:** 1.0.13
**Requires PHP:** 8.0
**License:** GPLv2 or later
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html

## What It Does

This add-on plugin exposes Wordfence security workflows through MCP (Model Context Protocol). Your AI assistant can monitor security status, run scans, and manage blocked IPs, lockouts, and allowlists.

**Part of the [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities) ecosystem.**

This is one piece of a bigger open WordPress automation stack that lets AI agents do real security operations inside WordPress instead of stopping at advice.

## Why This Is Cool

Security work is high-value and often boring in exactly the wrong way.

This add-on lets the agent inspect scan state, blocked IPs, lockouts, and live traffic, then take the smallest useful action. That means less dashboard hopping and fewer “we should deal with this later” moments.

## Documentation

- [Core Plugin: MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities)
- [MCP Wiki Home](https://github.com/bjornfix/mcp-expose-abilities/wiki)
- [Why Teams Use It](https://github.com/bjornfix/mcp-expose-abilities/wiki/Why-Teams-Use-It)
- [Use Cases](https://github.com/bjornfix/mcp-expose-abilities/wiki/Use-Cases)
- [Wordfence Add-On Guide](https://github.com/bjornfix/mcp-expose-abilities/wiki/Addon-Wordfence)
- [Getting Started](https://github.com/bjornfix/mcp-expose-abilities/wiki/Getting-Started)

## Requirements

- WordPress 6.9+
- PHP 8.0+
- [Abilities API](https://github.com/WordPress/abilities-api) plugin
- [MCP Adapter](https://github.com/WordPress/mcp-adapter) plugin
- [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities) core plugin
- [Wordfence Security](https://wordpress.org/plugins/wordfence/) plugin

## Installation

1. Install and activate MCP Expose Abilities
2. Install and activate Wordfence Security
3. Download the latest release from [Releases](https://github.com/bjornfix/mcp-abilities-wordfence/releases)
4. Upload via WordPress Admin > Plugins > Add New > Upload Plugin
5. Activate the plugin

## Changelog

### 1.0.13

- Updated declared WordPress compatibility to 7.0 for current plugin-check requirements

### 1.0.12

- Fixed `wordfence/list-live-traffic` to query the actual current Wordfence `wfhits` columns (`IP`, `URL`, `UA`, etc.) instead of stale field names
- Fixed live traffic results so existing tables return real rows instead of an empty `traffic` array

### 1.0.11

- Fixed scan status reporting to use Wordfence's real completion and monitor fields instead of treating `lastScanCompleted` as a timestamp
- Fixed `issues_count` to read from the real Wordfence issues table
- Improved scan-start verification by checking Wordfence monitor timestamps

### 1.0.10

- Fixed Wordfence table resolution on lowercase-table installs so live traffic and scan issues read the real `wfhits` and `wfissues` tables instead of treating them as missing

## Abilities (11)

| Ability | Description |
|---------|-------------|
| `wordfence/get-status` | Get overall security status (firewall, scan, issues, blocks) |
| `wordfence/get-scan-status` | Get current scan progress and status |
| `wordfence/start-scan` | Start a new Wordfence scan |
| `wordfence/list-blocked-ips` | List blocked IP addresses with reasons |
| `wordfence/list-live-traffic` | List recent live traffic events |
| `wordfence/block-ip` | Block an IP address temporarily or permanently |
| `wordfence/unblock-ip` | Remove an IP from the block list |
| `wordfence/list-scan-issues` | List security issues from scans |
| `wordfence/list-lockouts` | List IPs locked out from failed logins |
| `wordfence/unlock-ip` | Remove an IP from the lockout list |
| `wordfence/whitelist-ip` | Add an IP to the allowlist |

## Usage Examples

### Get security status

```json
{
  "ability_name": "wordfence/get-status",
  "parameters": {}
}
```

### Start a scan

```json
{
  "ability_name": "wordfence/start-scan",
  "parameters": {}
}
```

### Block an IP address

```json
{
  "ability_name": "wordfence/block-ip",
  "parameters": {
    "ip": "192.168.1.100",
    "reason": "Suspicious activity",
    "permanent": true
  }
}
```

## Changelog

### 1.0.9
- Fixed: `wordfence/list-live-traffic` now degrades cleanly to an empty result when the live-traffic table is unavailable on a site
- Fixed: `wordfence/list-scan-issues` now degrades cleanly to an empty result when the issues table is unavailable on a site

### 1.0.8
- Fixed: `wordfence/get-status` now derives firewall mode from actual WAF bootstrap state when config-only status is misleading
- Fixed: `wordfence/get-status` now reports completed scan time instead of scheduled scan time
- Fixed: `wordfence/get-status` now counts blocked IPs and lockouts through Wordfence APIs instead of mismatched raw table counts
- Fixed: `wordfence/start-scan` now reports whether the scan start was verified instead of always claiming success

### 1.0.7
- Fixed: Removed hard plugin header dependency on abilities-api to avoid slug-mismatch activation blocking
- Updated: README ability list and stable tag sync

### 1.0.6
- Fixed: `wordfence/get-status` callback now accepts null input from proxy adapters

### 1.0.5
- Fixed: no-input abilities now accept `null` input for proxy adapters that drop empty objects
- Fixed: added optional no-op input key (`_`) for proxy adapters that require non-empty objects

### 1.0.4
- Fixed: Compatibility for no-input abilities in proxy stacks that pass empty objects as arrays
- Fixed: Clarified inactive plugin message (`Wordfence plugin is not active.`)

### 1.0.3
- Simplify active checks and cache table existence per request

### 1.0.2
- Improved: Database queries now use esc_sql() and proper $wpdb->prepare() for WordPress.org compliance
- Improved: Added phpcs:ignore comments for justified direct database queries to Wordfence tables

### 1.0.1
- Fixed: Updated to use Wordfence 8.x wfBlock API instead of deprecated methods

### 1.0.0
- Initial release
- Added `wordfence/get-status` ability
- Added `wordfence/list-blocked-ips` ability
- Added `wordfence/block-ip` ability
- Added `wordfence/unblock-ip` ability
- Added `wordfence/list-scan-issues` ability
- Added `wordfence/list-lockouts` ability
- Added `wordfence/unlock-ip` ability
- Added `wordfence/whitelist-ip` ability

## License

GPL-2.0+

## Author

[Devenia](https://devenia.com) - We've been doing SEO and web development since 1993.

## Free and Open

Like the rest of the ecosystem, this add-on is free, completely open, and built for real operational use.

## Star and Share

If this add-on helps, please star the repo, share the ecosystem, and point people to the main wiki:

- https://github.com/bjornfix/mcp-expose-abilities
- https://github.com/bjornfix/mcp-expose-abilities/wiki

## Links

- [Core Plugin (MCP Expose Abilities)](https://github.com/bjornfix/mcp-expose-abilities)
- [Main Wiki](https://github.com/bjornfix/mcp-expose-abilities/wiki)
- [Wordfence Add-On Guide](https://github.com/bjornfix/mcp-expose-abilities/wiki/Addon-Wordfence)
