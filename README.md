# MCP Abilities - Wordfence

Wordfence security abilities for [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/). Monitor security status, manage blocked IPs, view scan issues, and control lockouts via the Abilities API.

**Stable tag: 1.0.3**

## Requirements

- [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities) (core plugin)
- [Wordfence Security](https://wordpress.org/plugins/wordfence/) plugin

## Abilities (8)

| Ability | Description |
|---------|-------------|
| `wordfence/get-status` | Get overall security status (firewall, scan, issues, blocks) |
| `wordfence/list-blocked-ips` | List blocked IP addresses with reasons |
| `wordfence/block-ip` | Block an IP address temporarily or permanently |
| `wordfence/unblock-ip` | Remove an IP from the block list |
| `wordfence/list-scan-issues` | List security issues from scans |
| `wordfence/list-lockouts` | List IPs locked out from failed logins |
| `wordfence/unlock-ip` | Remove an IP from the lockout list |
| `wordfence/whitelist-ip` | Add an IP to the allowlist |

## Installation

1. Install and activate [MCP Expose Abilities](https://github.com/bjornfix/mcp-expose-abilities)
2. Install and activate [Wordfence Security](https://wordpress.org/plugins/wordfence/)
3. Download the latest release zip
4. Upload to WordPress via Plugins > Add New > Upload Plugin
5. Activate the plugin

## Usage Examples

### Get Security Status

```json
{
  "ability": "wordfence/get-status",
  "parameters": {}
}
```

Response:
```json
{
  "success": true,
  "wordfence_version": "7.11.5",
  "firewall_mode": "enabled",
  "last_scan": "2024-01-15 14:30:00",
  "scan_running": false,
  "issues_count": 2,
  "blocked_ips_count": 15,
  "locked_out_count": 3,
  "is_premium": true
}
```

### Block an IP Address

```json
{
  "ability": "wordfence/block-ip",
  "parameters": {
    "ip": "192.168.1.100",
    "reason": "Suspicious activity",
    "permanent": true
  }
}
```

### List Scan Issues

```json
{
  "ability": "wordfence/list-scan-issues",
  "parameters": {
    "status": "new",
    "per_page": 20
  }
}
```

### Whitelist an IP

```json
{
  "ability": "wordfence/whitelist-ip",
  "parameters": {
    "ip": "203.0.113.50"
  }
}
```

## Changelog

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
