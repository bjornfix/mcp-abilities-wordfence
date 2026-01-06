<?php
/**
 * Plugin Name: MCP Abilities - Wordfence
 * Plugin URI: https://github.com/bjornfix/mcp-abilities-wordfence
 * Description: Wordfence security abilities for MCP. Monitor security status, manage blocked IPs, view scan issues, and control lockouts.
 * Version: 1.0.1
 * Author: Devenia
 * Author URI: https://devenia.com
 * License: GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 * Requires at least: 6.9
 * Requires PHP: 8.0
 * Requires Plugins: abilities-api
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
			echo '<div class="notice notice-error"><p><strong>MCP Abilities - Wordfence</strong> requires the <a href="https://github.com/WordPress/abilities-api">Abilities API</a> plugin to be installed and activated.</p></div>';
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
 * Get Wordfence database prefix.
 */
function mcp_wordfence_get_table_prefix(): string {
	global $wpdb;
	return $wpdb->base_prefix;
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
				'type'                 => 'object',
				'properties'           => array(),
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
			'execute_callback'    => function ( array $input = array() ): array {
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
				}

				global $wpdb;
				$prefix = mcp_wordfence_get_table_prefix();

				// Get Wordfence version.
				$version = defined( 'WORDFENCE_VERSION' ) ? WORDFENCE_VERSION : 'unknown';

				// Get firewall mode from config.
				$firewall_mode = 'unknown';
				if ( class_exists( 'wfConfig' ) ) {
					$waf_status = wfConfig::get( 'wafStatus', 'disabled' );
					$firewall_mode = $waf_status;
				}

				// Get last scan time.
				$last_scan = 'never';
				if ( class_exists( 'wfConfig' ) ) {
					$last_scan_time = wfConfig::get( 'lastScheduledScan', 0 );
					if ( $last_scan_time > 0 ) {
						$last_scan = gmdate( 'Y-m-d H:i:s', (int) $last_scan_time );
					}
				}

				// Check if scan is running.
				$scan_running = false;
				if ( class_exists( 'wfConfig' ) ) {
					$scan_running = (bool) wfConfig::get( 'scanRunning', 0 );
				}

				// Count issues.
				$issues_count = 0;
				$issues_table = $prefix . 'wfIssues';
				if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $issues_table ) ) === $issues_table ) {
					$issues_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$issues_table} WHERE status = 'new'" );
				}

				// Count blocked IPs.
				$blocked_count = 0;
				$blocks_table = $prefix . 'wfBlocks';
				if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $blocks_table ) ) === $blocks_table ) {
					$blocked_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$blocks_table}" );
				}

				// Count locked out users.
				$locked_count = 0;
				$lockout_table = $prefix . 'wfLockedOut';
				if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $lockout_table ) ) === $lockout_table ) {
					$locked_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$lockout_table}" );
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
					'last_scan'         => $last_scan,
					'scan_running'      => $scan_running,
					'issues_count'      => $issues_count,
					'blocked_ips_count' => $blocked_count,
					'locked_out_count'  => $locked_count,
					'is_premium'        => $is_premium,
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
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
				$all_blocks = wfBlock::ipBlocks( true );
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
				return current_user_can( 'manage_options' );
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
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
						$existing = wfBlock::findIPBlock( $ip );
						if ( $existing ) {
							return array(
								'success' => true,
								'ip'      => $ip,
								'message' => 'IP already blocked.',
							);
						}

						// DURATION_FOREVER = null for permanent, otherwise seconds.
						$duration = $permanent ? null : wfBlock::blockDuration();
						wfBlock::createIP( $reason, $ip, $duration );

						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => $permanent ? 'IP permanently blocked.' : 'IP blocked.',
						);
					} catch ( Exception $e ) {
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
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
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
						$block = wfBlock::findIPBlock( $ip );
						if ( ! $block ) {
							return array(
								'success' => true,
								'ip'      => $ip,
								'message' => 'IP was not in block list.',
							);
						}

						wfBlock::removeBlockIDs( array( $block->id ) );

						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => 'IP unblocked.',
						);
					} catch ( Exception $e ) {
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
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
				}

				global $wpdb;
				$prefix = mcp_wordfence_get_table_prefix();
				$table  = $prefix . 'wfIssues';

				// Check if table exists.
				if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) !== $table ) {
					return array(
						'success' => false,
						'message' => 'Wordfence issues table not found.',
					);
				}

				$status   = isset( $input['status'] ) ? sanitize_text_field( $input['status'] ) : 'new';
				$per_page = isset( $input['per_page'] ) ? min( 200, max( 1, (int) $input['per_page'] ) ) : 50;
				$page     = isset( $input['page'] ) ? max( 1, (int) $input['page'] ) : 1;
				$offset   = ( $page - 1 ) * $per_page;

				$where = '';
				if ( $status !== 'all' ) {
					$where = $wpdb->prepare( ' WHERE status = %s', $status );
				}

				$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}{$where}" );
				$pages = (int) ceil( $total / $per_page );

				$results = $wpdb->get_results(
					$wpdb->prepare(
						"SELECT id, time, status, type, severity, ignoreP, ignoreC, shortMsg, longMsg, data FROM {$table}{$where} ORDER BY time DESC LIMIT %d OFFSET %d",
						$per_page,
						$offset
					),
					ARRAY_A
				);

				$items = array();
				foreach ( $results as $row ) {
					$data = maybe_unserialize( $row['data'] );

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
				return current_user_can( 'manage_options' );
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
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

				// Get lockouts (prefetch=true to load all data).
				$all_lockouts = wfBlock::lockouts( true );
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
				return current_user_can( 'manage_options' );
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
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

				$lockout = wfBlock::lockoutForIP( $ip );
				if ( ! $lockout ) {
					return array(
						'success' => true,
						'ip'      => $ip,
						'message' => 'IP was not in lockout list.',
					);
				}

				wfBlock::removeBlockIDs( array( $lockout->id ) );

				return array(
					'success' => true,
					'ip'      => $ip,
					'message' => 'IP unlocked.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
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
			'description'         => 'Add an IP address to the Wordfence allowlist so it will never be blocked.',
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
				if ( ! mcp_wordfence_is_active() ) {
					return array(
						'success' => false,
						'message' => 'Wordfence Security plugin is not active.',
					);
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
						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => $result ? 'IP added to allowlist.' : 'IP already in allowlist.',
						);
					} catch ( Exception $e ) {
						return array(
							'success' => false,
							'ip'      => $ip,
							'message' => 'Failed to whitelist IP: ' . $e->getMessage(),
						);
					}
				}

				// Fallback: update whitelisted config.
				if ( class_exists( 'wfConfig' ) ) {
					$whitelist = wfConfig::get( 'whitelisted', '' );
					$ips       = array_filter( array_map( 'trim', explode( "\n", $whitelist ) ) );

					if ( in_array( $ip, $ips, true ) ) {
						return array(
							'success' => true,
							'ip'      => $ip,
							'message' => 'IP already in allowlist.',
						);
					}

					$ips[]        = $ip;
					$new_whitelist = implode( "\n", $ips );
					wfConfig::set( 'whitelisted', $new_whitelist );

					return array(
						'success' => true,
						'ip'      => $ip,
						'message' => 'IP added to allowlist.',
					);
				}

				return array(
					'success' => false,
					'ip'      => $ip,
					'message' => 'Could not access Wordfence configuration.',
				);
			},
			'permission_callback' => function (): bool {
				return current_user_can( 'manage_options' );
			},
			'meta'                => array(
				'annotations' => array(
					'readonly'    => false,
					'destructive' => false,
					'idempotent'  => true,
				),
			),
		)
	);
}
add_action( 'wp_abilities_api_init', 'mcp_register_wordfence_abilities' );
