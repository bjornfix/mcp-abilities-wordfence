# MCP Abilities - Wordfence

Wordfence security abilities for MCP. Monitor security status, manage blocked IPs, view scan issues, and control lockouts.

[![GitHub release](https://img.shields.io/github/v/release/bjornfix/mcp-abilities-wordfence)](https://github.com/bjornfix/mcp-abilities-wordfence/releases)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0)
[![WordPress](https://img.shields.io/badge/WordPress-6.9%2B-blue.svg)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net)

**Tested up to:** 7.0
**Stable tag:** 1.0.13
**License:** GPLv2 or later
**License URI:** https://www.gnu.org/licenses/gpl-2.0.html

## What It Does

Wordfence security abilities for MCP. Monitor security status, manage blocked IPs, view scan issues, and control lockouts.

This plugin is part of the Devenia MCP abilities ecosystem. It gives an MCP-capable agent a focused, authenticated way to work with Wordfence work inside WordPress through MCP.

**Example:** "Handle this WordPress maintenance task directly." - The agent can inspect the site, call the relevant ability, and return the result without making the human click through wp-admin for every step.

## The Real Workflow

In practice, the human should not have to memorize every ability name.

The normal pattern is:

1. install the base MCP stack
2. install only the add-ons the site actually needs
3. let the agent discover the available abilities
4. give the agent a clear task with boundaries
5. verify the result in WordPress

The human's job is mostly to describe the goal.
The agent's job is to figure out the mechanics.

## Why This Feels Different

Most WordPress automation still leaves the repetitive part to the human.

This plugin is different because the agent can act inside the site through a narrow, authenticated ability surface:

- inspect current site state before changing anything
- run the specific action needed for the task
- return structured results that are easy to verify
- keep the workflow inside WordPress instead of a separate checklist

That changes the experience from:

- `Here is what you should do in wp-admin`

to:

- `Tell the agent what needs doing, and let it carry out the work`

## Before vs After

### Before

- ask the AI what to do
- copy the answer into WordPress by hand
- click through wp-admin for the repetitive bits
- postpone maintenance because the task is tedious

### After

- tell the agent what needs doing
- let it inspect the relevant WordPress state
- let it run the targeted ability
- verify the result and move on

## Who It Is For

This is a good fit for:

- agencies managing WordPress sites with AI-assisted maintenance
- operators who want agents to do real WordPress work instead of producing instructions
- teams already using MCP Expose Abilities
- sites where this WordPress area is updated often enough to deserve automation

It is especially useful when the manual version is repetitive enough that important maintenance gets delayed.

## Documentation

Start with the main plugin page and base stack documentation:

- [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
- [Getting Started](https://github.com/bjornfix/mcp-expose-abilities/wiki/Getting-Started)
- [Install Order and Dependencies](https://github.com/bjornfix/mcp-expose-abilities/wiki/Install-Order-and-Dependencies)

If you are using an AI agent, the simplest instruction is often just:

- `Read https://github.com/bjornfix/mcp-expose-abilities and figure out the stack before making changes.`

## Start Here

If you are new to the stack, use this order:

1. Install **Abilities API**.
2. Install **MCP Adapter**.
3. Install **MCP Expose Abilities**.
4. Install **MCP Abilities - Wordfence**.
5. Confirm the new abilities appear in discovery.
6. Give the agent a clear task that uses this add-on.

If you skip base-stack verification and start with add-ons immediately, troubleshooting gets harder than it needs to be.

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

## Contributing

PRs welcome. Keep changes focused on the plugin's WordPress ability surface and preserve authenticated, explicit workflows.

## License

GPL-2.0+

## Author

[Devenia](https://devenia.com) - We've been doing SEO and web development since 1993.

## Links

- [Plugin Page](https://devenia.com/plugins/mcp-expose-abilities/#add-ons)
- [MCP Expose Abilities](https://devenia.com/plugins/mcp-expose-abilities/)
- [GitHub Releases](https://github.com/bjornfix/mcp-abilities-wordfence/releases)

## Star and Share

If this plugin saves you time or makes WordPress maintenance easier to verify, please:

- star the repo
- share it with people running WordPress sites
- point them to the main plugin page so they can see what the ecosystem can actually do

Why do it?

Because agent-friendly open WordPress tooling helps more of the boring but important work get done.
