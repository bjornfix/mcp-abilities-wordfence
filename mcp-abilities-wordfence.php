<?php
/**
 * Plugin Name: MCP Abilities - Wordfence
 * Plugin URI: https://github.com/bjornfix/mcp-abilities-wordfence
 * Description: Wordfence security abilities for MCP. Monitor security status, manage blocked IPs, view scan issues, and control lockouts.
 * Version: 1.0.16
 * Author: basicus
 * Author URI: https://profiles.wordpress.org/basicus/
 * License: GPL-2.0+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 6.9
 * Requires PHP: 8.0
 *
 * @package MCP_Abilities_Wordfence
 */

declare( strict_types=1 );

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Check if Abilities API is available.
 */
function mcp_wordfence_check_dependencies(): bool {
	if ( ! function_exists( 'wp_register_ability' ) ) {
		add_action( 'admin_notices', function () {
			echo '<div class="notice notice-error"><p><strong>MCP Abilities - Wordfence</strong> requires WordPress 6.9 or later with its built-in Abilities API.</p></div>';
		} );
		return false;
	}
	return true;
}

/**
 * Check if Wordfence is active.
 */
function mcp_wordfence_is_active(): bool {
	return class_exists( 'wordfence' ) || defined( 'WORDFENCE_VERSION' );
}

/**
 * Return a standard inactive error response for Wordfence abilities.
 */
function mcp_wordfence_require_active(): ?array {
	if ( mcp_wordfence_is_active() ) {
		return null;
	}
	return array(
		'success' => false,
		'message' => 'Wordfence plugin is not active.',
	);
}

/**
 * Read the firewall mode through the same native model as Wordfence's dashboard.
 *
 * @return string
 */
function mcp_wordfence_get_firewall_mode(): string {
	if ( ! class_exists( 'wfFirewall' ) ) {
		return 'unknown';
	}
	$mode = ( new wfFirewall() )->firewallMode();
	return in_array( $mode, array( 'enabled', 'learning-mode', 'disabled' ), true ) ? $mode : 'unknown';
}

/**
 * Return normalized Wordfence scan state.
 *
 * @return array<string, int|string|bool>
 */
function mcp_wordfence_get_scan_state(): array {
	$scan_running = false;
	$start_time   = 0;
	$end_time     = 0;
	$scheduled    = 0;
	$status       = '';
	$last_attempt = 0;
	$last_success = 0;

	if ( class_exists( 'wfConfig' ) ) {
		$scan_running   = class_exists( 'wfScanner' ) && method_exists( 'wfScanner', 'shared' )
			? (bool) wfScanner::shared()->isRunning()
			: (bool) wfConfig::get( 'scanRunning', 0 );
		$start_time     = (int) wfConfig::get( 'lastScheduledScanStart', 0 );
		$end_time       = class_exists( 'wfScanner' ) && method_exists( 'wfScanner', 'shared' )
			? (int) wfScanner::shared()->lastScanTime()
			: (int) wfConfig::get( 'scanTime', 0 );
		$scheduled      = class_exists( 'wfScanner' ) && method_exists( 'wfScanner', 'shared' )
			? (int) wfScanner::shared()->nextScheduledScanTime()
			: (int) wfConfig::get( 'lastScheduledScan', 0 );
		$last_attempt   = (int) wfConfig::get( 'scanMonitorLastAttempt', 0, false );
		$last_success   = (int) wfConfig::get( 'scanMonitorLastSuccess', 0, false );
		$last_completed = (string) wfConfig::get( 'lastScanCompleted', '' );
		$failure_type   = (string) wfConfig::get( 'lastScanFailureType', '' );
		$has_failed     = class_exists( 'wfIssues' ) && method_exists( 'wfIssues', 'hasScanFailed' )
			? wfIssues::hasScanFailed()
			: false;

		if ( '' === $last_completed || false === $last_completed ) {
			$status = '';
		} elseif ( 'ok' === $last_completed ) {
			$status = 'ok';
		} elseif ( $has_failed ) {
			$status = (string) $has_failed;
		} elseif ( '' !== $failure_type ) {
			$status = $failure_type;
		} else {
			$status = $last_completed;
		}
	}

	return array(
		'scan_running'       => $scan_running,
		'last_scan_start'    => $start_time ? gmdate( 'Y-m-d H:i:s', $start_time ) : 'never',
		'last_scan_end'      => $end_time ? gmdate( 'Y-m-d H:i:s', $end_time ) : 'never',
		'last_scheduled'     => $scheduled ? gmdate( 'Y-m-d H:i:s', $scheduled ) : 'never',
		'last_scan_status'   => $status,
		'last_scan_start_ts' => $start_time,
		'last_scan_end_ts'   => $end_time,
		'last_scheduled_ts'  => $scheduled,
		'last_attempt_ts'    => $last_attempt,
		'last_success_ts'    => $last_success,
	);
}

/**
 * Count blocked IPs using Wordfence's public API when available.
 *
 * @return int
 */
function mcp_wordfence_count_blocked_ips(): int {
	if ( ! class_exists( 'wfBlock' ) ) {
		return 0;
	}

	$blocks = wfBlock::ipBlocks( true );
	return is_array( $blocks ) ? count( $blocks ) : 0;
}

/**
 * Count lockouts using Wordfence's public API when available.
 *
 * @return int
 */
function mcp_wordfence_count_lockouts(): int {
	if ( ! class_exists( 'wfBlock' ) ) {
		return 0;
	}

	$lockouts = wfBlock::lockouts( false );
	return is_array( $lockouts ) ? count( $lockouts ) : 0;
}

/**
 * Resolve a Wordfence table name using Wordfence's own casing rules when available.
 *
 * @param string $table Unprefixed Wordfence table name, e.g. `wfHits`.
 * @return string
 */
function mcp_wordfence_get_table_name( string $table ): string {
	if ( class_exists( 'wfDB' ) && method_exists( 'wfDB', 'networkTable' ) ) {
		return wfDB::networkTable( $table );
	}

	global $wpdb;
	$use_lowercase = false;

	if ( class_exists( 'wfSchema' ) && method_exists( 'wfSchema', 'usingLowercase' ) ) {
		$use_lowercase = (bool) wfSchema::usingLowercase();
	} else {
		$use_lowercase = (bool) get_option( 'wordfence_case', false );
	}

	if ( $use_lowercase ) {
		$table = strtolower( $table );
	}

	return $wpdb->base_prefix . $table;
}

/**
 * Check if a Wordfence table exists (cached per request).
 *
 * @param string $table Table name.
 * @return bool
 */
function mcp_wordfence_table_exists( string $table ): bool {
	static $cache = array();
	if ( isset( $cache[ $table ] ) ) {
		return $cache[ $table ];
	}

	global $wpdb;
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Real-time table existence.
	$exists = ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table );
	$cache[ $table ] = $exists;

	return $exists;
}

/**
 * Register Wordfence abilities.
 */
function mcp_register_wordfence_abilities(): void {
	if ( ! mcp_wordfence_check_dependencies() ) {
		return;
	}

	// =========================================================================
	// WORDFENCE - Get Security Status
	// =========================================================================
	wp_register_ability(
		'wordfence/get-status',
		array(
			'label'               => 'Get Wordfence Security Status',
			'description'         => 'Get overall Wordfence security status including firewall mode, last scan time, issues count, and blocked IPs count.',
			'category'            => 'site',
			'input_schema'        => array(
				// Compatibility: some proxy adapters drop empty objects entirely.
				// Accept null input and a no-op field for non-empty object transport.
				'type'                 => array( 'object', 'array', 'null' ),
				'properties'           => array(
					'_' => array(
						'type'        => array( 'string', 'number', 'boolean', 'null' ),
						'description' => 'Optional no-op compatibility field.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success'           => array( 'type' => 'boolean' ),
					'wordfence_version' => array( 'type' => 'string' ),
					'firewall_mode'     => array( 'type' => 'string' ),
					'last_scan'         => array( 'type' => 'string' ),
					'scan_running'      => array( 'type' => 'boolean' ),
					'issues_count'      => array( 'type' => 'integer' ),
					'blocked_ips_count' => array( 'type' => 'integer' ),
					'locked_out_count'  => array( 'type' => 'integer' ),
					'is_premium'        => array( 'type' => 'boolean' ),
					'message'           => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( $input = null ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				// Get Wordfence version.
				$version = defined( 'WORDFENCE_VERSION' ) ? WORDFENCE_VERSION : 'unknown';

				$firewall_mode = mcp_wordfence_get_firewall_mode();
				$scan_state    = mcp_wordfence_get_scan_state();

				// Count issues directly from the Wordfence issues table.
				$issues_count = 0;
				global $wpdb;
				$issues_table = mcp_wordfence_get_table_name( 'wfIssues' );
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Real-time security status, Wordfence table.
				if ( mcp_wordfence_table_exists( $issues_table ) ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Wordfence table with hardcoded suffix.
					$issues_count = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM `' . esc_sql( $issues_table ) . '` WHERE status = %s', 'new' ) );
				}

				if ( ! mcp_wordfence_table_exists( $issues_table ) || $wpdb->last_error || ! class_exists( 'wfBlock' ) ) {
					return array( 'success' => false, 'message' => 'Wordfence security status is unavailable because its data could not be read.' );
				}

				$blocked_count = mcp_wordfence_count_blocked_ips();
				$block_error = $wpdb->last_error;
				$locked_count  = mcp_wordfence_count_lockouts();
				if ( $block_error || $wpdb->last_error ) {
					return array( 'success' => false, 'message' => 'Wordfence block or lockout counts could not be read.' );
				}

				// Check premium status.
				$is_premium = false;
				if ( class_exists( 'wfConfig' ) ) {
					$is_premium = (bool) wfConfig::get( 'isPaid', false );
				}

				return array(
					'success'           => true,
					'wordfence_version' => $version,
					'firewall_mode'     => $firewall_mode,
					'last_scan'         => (string) $scan_state['last_scan_end'],
					'scan_running'      => (bool) $scan_state['scan_running'],
					'issues_count'      => $issues_count,
					'blocked_ips_count' => $blocked_count,
					'locked_out_count'  => $locked_count,
					'is_premium'        => $is_premium,
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - Get Scan Status
	// =========================================================================
	wp_register_ability(
		'wordfence/get-scan-status',
		array(
			'label'               => 'Get Scan Status',
			'description'         => 'Get Wordfence scan status and timestamps.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => array( 'object', 'array', 'null' ),
				'properties'           => array(
					'_' => array(
						'type'        => array( 'string', 'number', 'boolean', 'null' ),
						'description' => 'Optional no-op compatibility field.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success'          => array( 'type' => 'boolean' ),
					'scan_running'     => array( 'type' => 'boolean' ),
					'last_scan_start'  => array( 'type' => 'string', 'description' => 'UTC start time of the last scheduled scan, or never. This does not cover manual starts.' ),
					'last_scan_end'    => array( 'type' => 'string', 'description' => 'UTC time when Wordfence last recorded a finished scan, including failures. Check last_scan_status.' ),
					'last_scheduled'   => array( 'type' => 'string', 'description' => 'Next scheduled scan time in UTC, despite the legacy field name.' ),
					'last_scan_status' => array( 'type' => 'string' ),
					'message'          => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function (): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				if ( ! class_exists( 'wfConfig' ) ) {
					return array(
						'success' => false,
						'message' => 'Wordfence configuration class not available.',
					);
				}

				$scan_state = mcp_wordfence_get_scan_state();

				return array(
					'success'          => true,
					'scan_running'     => (bool) $scan_state['scan_running'],
					'last_scan_start'  => (string) $scan_state['last_scan_start'],
					'last_scan_end'    => (string) $scan_state['last_scan_end'],
					'last_scheduled'   => (string) $scan_state['last_scheduled'],
					'last_scan_status' => (string) $scan_state['last_scan_status'],
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - Start Scan
	// =========================================================================
	wp_register_ability(
		'wordfence/start-scan',
		array(
			'label'               => 'Start Scan',
			'description'         => 'Start a Wordfence scan if supported by the installed version.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => array( 'object', 'array', 'null' ),
				'properties'           => array(
					'_' => array(
						'type'        => array( 'string', 'number', 'boolean', 'null' ),
						'description' => 'Optional no-op compatibility field.',
					),
				),
				'additionalProperties' => false,
			),
				'output_schema'       => array(
					'type'       => 'object',
					'properties' => array(
						'success'  => array( 'type' => 'boolean' ),
						'verified' => array( 'type' => 'boolean' ),
						'message'  => array( 'type' => 'string' ),
					),
				),
			'execute_callback'    => function (): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				$before  = mcp_wordfence_get_scan_state();
				$invoked = false;

				if ( class_exists( 'wfScanEngine' ) && method_exists( 'wfScanEngine', 'startScan' ) ) {
					// phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- Third-party API.
					$scan_error = wfScanEngine::startScan();
					$invoked    = true;

					if ( ! empty( $scan_error ) ) {
						return array(
							'success'  => false,
							'verified' => false,
							'message'  => wp_strip_all_tags( (string) $scan_error ),
						);
					}
				}

				if ( ! $invoked ) {
					return array(
						'success'  => false,
						'verified' => false,
						'message'  => 'Scan start is not supported by this Wordfence version.',
					);
				}

				$after    = mcp_wordfence_get_scan_state();
				$verified = (bool) $after['scan_running']
					|| ( (int) $after['last_success_ts'] > (int) $before['last_success_ts'] )
					|| ( (int) $after['last_scan_end_ts'] > (int) $before['last_scan_end_ts'] );

				if ( $verified ) {
					return array(
						'success'  => true,
						'verified' => true,
						'message'  => 'Scan started.',
					);
				}

				return array(
					'success'  => true,
					'verified' => false,
					'message'  => 'Scan start was requested, but Wordfence did not expose an updated scan state yet.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => false,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - List Blocked IPs
	// =========================================================================
	wp_register_ability(
		'wordfence/list-blocked-ips',
		array(
			'label'               => 'List Blocked IPs',
			'description'         => 'List all currently blocked IP addresses with reason and expiration time.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'properties'           => array(
					'per_page' => array(
						'type'        => 'integer',
						'default'     => 50,
						'minimum'     => 1,
						'maximum'     => 200,
						'description' => 'Number of results per page (max 200).',
					),
					'page'     => array(
						'type'        => 'integer',
						'default'     => 1,
						'minimum'     => 1,
						'description' => 'Page number.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'items'   => array( 'type' => 'array' ),
					'total'   => array( 'type' => 'integer' ),
					'page'    => array( 'type' => 'integer' ),
					'pages'   => array( 'type' => 'integer' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input = array() ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				if ( ! class_exists( 'wfBlock' ) ) {
					return array(
						'success' => false,
						'message' => 'wfBlock class not available.',
					);
				}

				$per_page = isset( $input['per_page'] ) ? min( 200, max( 1, (int) $input['per_page'] ) ) : 50;
				$page     = isset( $input['page'] ) ? max( 1, (int) $input['page'] ) : 1;
				$offset   = ( $page - 1 ) * $per_page;

				// Get IP blocks only (prefetch=true to load all data).
				global $wpdb;
				$all_blocks = wfBlock::ipBlocks( true );
				if ( $wpdb->last_error || ! is_array( $all_blocks ) ) {
					return array( 'success' => false, 'message' => 'Wordfence IP blocks could not be read.' );
				}
				$total      = count( $all_blocks );
				$pages      = (int) ceil( $total / $per_page );

				// Slice for pagination.
				$blocks = array_slice( $all_blocks, $offset, $per_page );

				$items = array();
				foreach ( $blocks as $block ) {
					$items[] = array(
						'id'           => $block->id,
						'ip'           => $block->ip,
						'blocked_time' => gmdate( 'Y-m-d H:i:s', (int) $block->blockedTime ),
						'reason'       => $block->reason,
						'type'         => wfBlock::nameForType( $block->type ),
						'expiration'   => $block->expiration > 0 ? gmdate( 'Y-m-d H:i:s', (int) $block->expiration ) : 'never',
					);
				}

				return array(
					'success' => true,
					'items'   => $items,
					'total'   => $total,
					'page'    => $page,
					'pages'   => $pages,
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - List Live Traffic
	// =========================================================================
	wp_register_ability(
		'wordfence/list-live-traffic',
		array(
			'label'               => 'List Live Traffic',
			'description'         => 'List recent Wordfence live traffic entries (read-only).',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'properties'           => array(
					'per_page' => array(
						'type'        => 'integer',
						'default'     => 50,
						'minimum'     => 1,
						'maximum'     => 200,
						'description' => 'Number of results per page (max 200).',
					),
					'page'     => array(
						'type'        => 'integer',
						'default'     => 1,
						'minimum'     => 1,
						'description' => 'Page number.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'traffic' => array( 'type' => 'array' ),
					'total'   => array( 'type' => 'integer' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input = array() ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				global $wpdb;
				$table = mcp_wordfence_get_table_name( 'wfHits' );

					if ( ! mcp_wordfence_table_exists( $table ) ) {
						return array(
							'success' => false,
							'traffic' => array(),
							'total'   => 0,
							'message' => 'Wordfence live traffic is unavailable on this site because the live traffic table is not present.',
						);
					}

				$per_page = min( 200, max( 1, (int) ( $input['per_page'] ?? 50 ) ) );
				$page     = max( 1, (int) ( $input['page'] ?? 1 ) );
				$offset   = ( $page - 1 ) * $per_page;

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Wordfence live traffic data.
					$rows = $wpdb->get_results(
						$wpdb->prepare(
							'SELECT id, INET6_NTOA(IP) AS ip, ctime, URL AS url, UA AS ua, action, userID, statusCode, referer, actionDescription, actionData FROM `' . esc_sql( $table ) . '` ORDER BY ctime DESC LIMIT %d OFFSET %d',
							$per_page,
							$offset
						),
						ARRAY_A
					);
					if ( $wpdb->last_error || ! is_array( $rows ) ) {
						return array( 'success' => false, 'message' => 'Wordfence traffic could not be read.' );
					}
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Read-only count query for pagination metadata.
					$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) );
					if ( $wpdb->last_error ) {
						return array( 'success' => false, 'message' => 'Wordfence traffic count could not be read.' );
					}

					return array(
						'success' => true,
						'traffic' => $rows,
						'total'   => $total,
					);
				},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - Block IP
	// =========================================================================
	wp_register_ability(
		'wordfence/block-ip',
		array(
			'label'               => 'Block IP Address',
			'description'         => 'Block an IP address. Can set as permanent or temporary block.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'ip' ),
				'properties'           => array(
					'ip'        => array(
						'type'        => 'string',
						'description' => 'IP address to block (IPv4 or IPv6).',
					),
					'reason'    => array(
						'type'        => 'string',
						'default'     => 'Blocked via MCP',
						'description' => 'Reason for blocking.',
					),
					'permanent' => array(
						'type'        => 'boolean',
						'default'     => false,
						'description' => 'Make this a permanent block.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'ip'      => array( 'type' => 'string' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				$ip = sanitize_text_field( $input['ip'] );

				// Validate IP address.
				if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return array(
						'success' => false,
						'ip'      => $ip,
						'message' => 'Invalid IP address format.',
					);
				}

				$reason    = isset( $input['reason'] ) ? sanitize_text_field( $input['reason'] ) : 'Blocked via MCP';
				$permanent = ! empty( $input['permanent'] );

				// Use Wordfence 8.x wfBlock class.
				if ( class_exists( 'wfBlock' ) ) {
					try {
						// Check if already blocked.
						global $wpdb;
						$existing = wfBlock::findIPBlock( $ip );
						if ( $wpdb->last_error ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => 'The current Wordfence restriction could not be read; no change was made.' );
						}
						if ( $existing ) {
							if ( $permanent !== ( 0 === (int) $existing->expiration ) ) {
								return array( 'success' => false, 'ip' => $ip, 'message' => 'An existing block has a different duration. Its settings were preserved; review it before replacing it.' );
							}
							return array(
								'success' => true,
								'ip'      => $ip,
								'message' => 'IP already blocked.',
							);
						}

						// Use Wordfence's duration constant for permanent blocks.
						$duration = $permanent ? wfBlock::DURATION_FOREVER : wfBlock::blockDuration();
						if ( ! $permanent && $duration <= 0 ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => 'Wordfence has no positive temporary-block duration configured.' );
						}
						$valid = wfBlock::validate( array( 'type' => 'ip-address', 'ip' => $ip, 'reason' => $reason, 'duration' => $duration ) );
						if ( true !== $valid ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => wp_strip_all_tags( (string) $valid ) );
						}
						wfBlock::createIP( $reason, $ip, $duration );
						$saved = wfBlock::findIPBlock( $ip );
						if ( ! $saved || ( $permanent && 0 !== (int) $saved->expiration ) || ( ! $permanent && (int) $saved->expiration <= time() ) ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => 'Wordfence did not persist the requested IP block. The address may be allowlisted or storage may be unavailable.' );
						}

						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => $permanent ? 'IP permanently blocked.' : 'IP blocked.',
						);
					} catch ( Throwable $e ) {
						return array(
							'success' => false,
							'ip'      => $ip,
							'message' => 'Failed to block IP: ' . $e->getMessage(),
						);
					}
				}

				return array(
					'success' => false,
					'ip'      => $ip,
					'message' => 'wfBlock class not available.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
				'meta'                => array(
					'annotations' => array(
						'readonly'    => false,
						'destructive' => true,
						'idempotent'  => true,
					),
				),
		)
	);

	// =========================================================================
	// WORDFENCE - Unblock IP
	// =========================================================================
	wp_register_ability(
		'wordfence/unblock-ip',
		array(
			'label'               => 'Unblock IP Address',
			'description'         => 'Remove an IP address from the block list.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'ip' ),
				'properties'           => array(
					'ip' => array(
						'type'        => 'string',
						'description' => 'IP address to unblock (IPv4 or IPv6).',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'ip'      => array( 'type' => 'string' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				$ip = sanitize_text_field( $input['ip'] );

				// Validate IP address.
				if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return array(
						'success' => false,
						'ip'      => $ip,
						'message' => 'Invalid IP address format.',
					);
				}

				// Use Wordfence 8.x wfBlock class.
				if ( class_exists( 'wfBlock' ) ) {
					try {
						global $wpdb;
						$block = wfBlock::findIPBlock( $ip );
						if ( $wpdb->last_error ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => 'The current Wordfence restriction could not be read; no change was made.' );
						}
						if ( ! $block ) {
							return array(
								'success' => true,
								'ip'      => $ip,
								'message' => 'IP was not in block list.',
							);
						}

						$removed = wfBlock::removeBlockIDs( array( $block->id ) );
						if ( ! $removed || wfBlock::findIPBlock( $ip ) || $wpdb->last_error ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => 'An IP block remains. Review the current block list before another change.' );
						}

						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => 'IP unblocked.',
						);
					} catch ( Throwable $e ) {
						return array(
							'success' => false,
							'ip'      => $ip,
							'message' => 'Failed to unblock IP: ' . $e->getMessage(),
						);
					}
				}

				return array(
					'success' => false,
					'ip'      => $ip,
					'message' => 'wfBlock class not available.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
				'meta'                => array(
					'annotations' => array(
						'readonly'    => false,
						'destructive' => true,
						'idempotent'  => true,
					),
				),
		)
	);

	// =========================================================================
	// WORDFENCE - List Scan Issues
	// =========================================================================
	wp_register_ability(
		'wordfence/list-scan-issues',
		array(
			'label'               => 'List Scan Issues',
			'description'         => 'List security issues found by Wordfence scans.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'properties'           => array(
					'status'   => array(
						'type'        => 'string',
						'enum'        => array( 'new', 'ignored', 'all' ),
						'default'     => 'new',
						'description' => 'Filter by issue status.',
					),
					'per_page' => array(
						'type'        => 'integer',
						'default'     => 50,
						'minimum'     => 1,
						'maximum'     => 200,
						'description' => 'Number of results per page (max 200).',
					),
					'page'     => array(
						'type'        => 'integer',
						'default'     => 1,
						'minimum'     => 1,
						'description' => 'Page number.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'items'   => array( 'type' => 'array' ),
					'total'   => array( 'type' => 'integer' ),
					'page'    => array( 'type' => 'integer' ),
					'pages'   => array( 'type' => 'integer' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input = array() ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				global $wpdb;
				$table = mcp_wordfence_get_table_name( 'wfIssues' );

				// Check if table exists.
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Table existence check.
					if ( ! mcp_wordfence_table_exists( $table ) ) {
						return array(
							'success' => false,
							'items'   => array(),
							'total'   => 0,
							'page'    => 1,
							'pages'   => 0,
							'message' => 'Wordfence scan issues are unavailable on this site because the issues table is not present.',
						);
					}

				$status   = isset( $input['status'] ) ? sanitize_text_field( $input['status'] ) : 'new';
				$per_page = isset( $input['per_page'] ) ? min( 200, max( 1, (int) $input['per_page'] ) ) : 50;
				$page     = isset( $input['page'] ) ? max( 1, (int) $input['page'] ) : 1;
				$offset   = ( $page - 1 ) * $per_page;

					// Build query based on status filter.
					// Using Wordfence's wfIssues table which is created and managed by Wordfence plugin.
					// Table name is safe: WordPress base_prefix + hardcoded 'wfIssues' suffix.
					if ( 'all' === $status ) {
						// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
						$total   = (int) $wpdb->get_var(
							$wpdb->prepare(
								'SELECT COUNT(*) FROM %i',
								$table
							)
						);
						$count_error = $wpdb->last_error;
						$results = $wpdb->get_results(
							$wpdb->prepare(
								'SELECT id, time, status, type, severity, ignoreP, ignoreC, shortMsg, longMsg, data FROM %i ORDER BY time DESC LIMIT %d OFFSET %d',
								$table,
								$per_page,
								$offset
							),
							ARRAY_A
						);
						// phpcs:enable
					} else {
						// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
						$total   = (int) $wpdb->get_var(
							$wpdb->prepare(
								'SELECT COUNT(*) FROM %i WHERE status = %s',
								$table,
								$status
							)
						);
						$count_error = $wpdb->last_error;
						$results = $wpdb->get_results(
							$wpdb->prepare(
								'SELECT id, time, status, type, severity, ignoreP, ignoreC, shortMsg, longMsg, data FROM %i WHERE status = %s ORDER BY time DESC LIMIT %d OFFSET %d',
								$table,
								$status,
								$per_page,
								$offset
						),
						ARRAY_A
					);
					// phpcs:enable
				}
				if ( $count_error || $wpdb->last_error || ! is_array( $results ) ) {
					return array( 'success' => false, 'message' => 'Wordfence scan issues could not be read.' );
				}
				$pages = (int) ceil( $total / $per_page );

				$items = array();
				foreach ( $results as $row ) {
					$data = is_serialized( $row['data'] ) ? unserialize( $row['data'], array( 'allowed_classes' => false ) ) : array();
					$data = is_array( $data ) ? $data : array();

					$items[] = array(
						'id'          => (int) $row['id'],
						'time'        => gmdate( 'Y-m-d H:i:s', (int) $row['time'] ),
						'status'      => $row['status'],
						'type'        => $row['type'],
						'severity'    => (int) $row['severity'],
						'short_msg'   => $row['shortMsg'],
						'long_msg'    => $row['longMsg'],
						'can_ignore'  => (bool) $row['ignoreP'],
						'file'        => isset( $data['file'] ) ? $data['file'] : null,
					);
				}

				return array(
					'success' => true,
					'items'   => $items,
					'total'   => $total,
					'page'    => $page,
					'pages'   => $pages,
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - List Locked Out Users
	// =========================================================================
	wp_register_ability(
		'wordfence/list-lockouts',
		array(
			'label'               => 'List Locked Out Users',
			'description'         => 'List IP addresses currently locked out due to failed login attempts.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'properties'           => array(
					'per_page' => array(
						'type'        => 'integer',
						'default'     => 50,
						'minimum'     => 1,
						'maximum'     => 200,
						'description' => 'Number of results per page (max 200).',
					),
					'page'     => array(
						'type'        => 'integer',
						'default'     => 1,
						'minimum'     => 1,
						'description' => 'Page number.',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'items'   => array( 'type' => 'array' ),
					'total'   => array( 'type' => 'integer' ),
					'page'    => array( 'type' => 'integer' ),
					'pages'   => array( 'type' => 'integer' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input = array() ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				if ( ! class_exists( 'wfBlock' ) ) {
					return array(
						'success' => false,
						'message' => 'wfBlock class not available.',
					);
				}

				$per_page = isset( $input['per_page'] ) ? min( 200, max( 1, (int) $input['per_page'] ) ) : 50;
				$page     = isset( $input['page'] ) ? max( 1, (int) $input['page'] ) : 1;
				$offset   = ( $page - 1 ) * $per_page;

					// Avoid prefetch-heavy mode when listing lockouts.
					global $wpdb;
					$all_lockouts = wfBlock::lockouts( false );
					if ( $wpdb->last_error || ! is_array( $all_lockouts ) ) {
						return array( 'success' => false, 'message' => 'Wordfence lockouts could not be read.' );
					}
				$total        = count( $all_lockouts );
				$pages        = (int) ceil( $total / $per_page );

				// Slice for pagination.
				$lockouts = array_slice( $all_lockouts, $offset, $per_page );

				$items = array();
				foreach ( $lockouts as $lockout ) {
					$items[] = array(
						'id'            => $lockout->id,
						'ip'            => $lockout->ip,
						'blocked_time'  => gmdate( 'Y-m-d H:i:s', (int) $lockout->blockedTime ),
						'reason'        => $lockout->reason,
						'expiration'    => $lockout->expiration > 0 ? gmdate( 'Y-m-d H:i:s', (int) $lockout->expiration ) : 'never',
						'blocked_hits'  => (int) $lockout->blockedHits,
					);
				}

				return array(
					'success' => true,
					'items'   => $items,
					'total'   => $total,
					'page'    => $page,
					'pages'   => $pages,
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => true,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - Unlock IP
	// =========================================================================
	wp_register_ability(
		'wordfence/unlock-ip',
		array(
			'label'               => 'Unlock IP Address',
			'description'         => 'Remove an IP address from the lockout list (for failed login attempts).',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'ip' ),
				'properties'           => array(
					'ip' => array(
						'type'        => 'string',
						'description' => 'IP address to unlock (IPv4 or IPv6).',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'ip'      => array( 'type' => 'string' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				$ip = sanitize_text_field( $input['ip'] );

				// Validate IP address.
				if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return array(
						'success' => false,
						'ip'      => $ip,
						'message' => 'Invalid IP address format.',
					);
				}

				if ( ! class_exists( 'wfBlock' ) ) {
					return array(
						'success' => false,
						'ip'      => $ip,
						'message' => 'wfBlock class not available.',
					);
				}

				global $wpdb;
				$lockout = wfBlock::lockoutForIP( $ip );
				if ( $wpdb->last_error ) {
					return array( 'success' => false, 'ip' => $ip, 'message' => 'The current Wordfence restriction could not be read; no change was made.' );
				}
				if ( ! $lockout ) {
					return array(
						'success' => true,
						'ip'      => $ip,
						'message' => 'IP was not in lockout list.',
					);
				}

				$removed = wfBlock::removeBlockIDs( array( $lockout->id ) );
				if ( ! $removed || wfBlock::lockoutForIP( $ip ) || $wpdb->last_error ) {
					return array( 'success' => false, 'ip' => $ip, 'message' => 'The login lockout remains. Review the current lockout list before another change.' );
				}

				return array(
					'success' => true,
					'ip'      => $ip,
					'message' => 'IP unlocked.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => true,
					'idempotent'  => true,
				),
			),
		)
	);

	// =========================================================================
	// WORDFENCE - Whitelist IP
	// =========================================================================
	wp_register_ability(
		'wordfence/whitelist-ip',
		array(
			'label'               => 'Whitelist IP Address',
			'description'         => 'Add an IP address to the Wordfence allowlist. Traffic from the address bypasses Wordfence security checks; this is broader than releasing a lockout.',
			'category'            => 'site',
			'input_schema'        => array(
				'type'                 => 'object',
				'required'             => array( 'ip' ),
				'properties'           => array(
					'ip' => array(
						'type'        => 'string',
						'description' => 'IP address to whitelist (IPv4 or IPv6).',
					),
				),
				'additionalProperties' => false,
			),
			'output_schema'       => array(
				'type'       => 'object',
				'properties' => array(
					'success' => array( 'type' => 'boolean' ),
					'ip'      => array( 'type' => 'string' ),
					'message' => array( 'type' => 'string' ),
				),
			),
			'execute_callback'    => function ( array $input ): array {
				if ( $error = mcp_wordfence_require_active() ) {
					return $error;
				}

				$ip = sanitize_text_field( $input['ip'] );

				// Validate IP address.
				if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return array(
						'success' => false,
						'ip'      => $ip,
						'message' => 'Invalid IP address format.',
					);
				}

				// Use Wordfence's official API.
				if ( method_exists( 'wordfence', 'whitelistIP' ) ) {
					try {
						$result = wordfence::whitelistIP( $ip );
						$saved = class_exists( 'wfConfig' ) ? array_map( 'trim', explode( ',', (string) wfConfig::get( 'whitelisted', '', false ) ) ) : array();
						if ( ! in_array( $ip, $saved, true ) ) {
							return array( 'success' => false, 'ip' => $ip, 'message' => 'The native allowlist update could not be verified.' );
						}
						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => $result ? 'IP added to allowlist.' : 'IP already in allowlist.',
						);
					} catch ( Throwable $e ) {
						return array(
							'success' => false,
							'ip'      => $ip,
							'message' => 'Failed to whitelist IP: ' . $e->getMessage(),
						);
					}
				}

				return array(
					'success' => false,
					'ip'      => $ip,
					'message' => 'The native Wordfence allowlist function is unavailable.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( is_multisite() ? 'manage_network' : 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => true,
					'idempotent'  => true,
				),
			),
		)
	);
}
add_action( 'wp_abilities_api_init', 'mcp_register_wordfence_abilities' );
