<?php
/** Regression tests for the public Wordfence callbacks. */
define( 'ABSPATH', sys_get_temp_dir() . '/wordfence-ability-test/' );
$GLOBALS['abilities'] = array();
function add_action( ...$args ) {}
function wp_register_ability( $name, $args ) { $GLOBALS['abilities'][ $name ] = $args; }
function is_multisite() { return ! empty( $GLOBALS['multisite'] ); }
function current_user_can( $cap ) { return 'manage_options' === $cap; }
function esc_sql( $value ) { return $value; }
define( 'ARRAY_A', 'ARRAY_A' );
function sanitize_text_field( $value ) { return trim( strip_tags( $value ) ); }
function wp_strip_all_tags( $value ) { return strip_tags( $value ); }
function trailingslashit( $value ) { return rtrim( $value, '/' ) . '/'; }
function untrailingslashit( $value ) { return rtrim( $value, '/' ); }
class wordfence {
 public static $write = false;
 public static function whitelistIP( $ip ) { if ( self::$write ) { wfConfig::$data['whitelisted'] = $ip; } return true; }
}
class wfDB {
 public static function networkTable( $name ) { return 'wp_' . $name; }
}
class FixtureDB {
 public $last_error = '';
 public function esc_like( $value ) { return $value; }
 public function prepare( $query, ...$args ) { return vsprintf( str_replace( array( '%i', '%s' ), '%s', $query ), $args ); }
 public function get_var( $query ) { if ( str_starts_with( $query, 'SHOW TABLES' ) ) { return substr( $query, strlen( 'SHOW TABLES LIKE ' ) ); } $this->last_error = 'test database unavailable'; return null; }
 public function get_results( ...$args ) { $this->last_error = 'test database unavailable'; return null; }
}
$GLOBALS['wpdb'] = new FixtureDB();
class wfConfig {
 public static $data = array( 'wafStatus' => 'enabled' );
 public static function get( $name, $default = null ) { return self::$data[ $name ] ?? $default; }
}
class wfFirewall {
 public static function shared() { return new self(); }
 public function firewallMode() { return 'disabled'; }
}
class wfBlock {
 const DURATION_FOREVER = 0;
 public static function validate( $payload ) { return true; }
 public static $block = null;
 public static $create = false;
 public static function findIPBlock( $ip ) { return self::$block; }
 public static function lockoutForIP( $ip ) { return self::$block; }
 public static function createIP( $reason, $ip, $duration ) { if ( self::$create ) { self::$block = (object) array( 'id' => 2, 'expiration' => $duration ? time() + $duration : 0 ); } return false; }
 public static function blockDuration() { return 60; }
 public static function removeBlockIDs( ...$args ) { return false; }
}
class wfUserIPRange {
 public function __construct( private $range ) {}
 public function isIPInRange( $ip ) { return $this->range === $ip; }
}
class wfScanner {
 public static $scheduled = 100;
 public static function shared() { return new self(); }
 public function isRunning() { return false; }
 public function lastScanTime() { return 0; }
 public function nextScheduledScanTime() { return self::$scheduled; }
}
class wfScanEngine {
 public static function startScan() { wfScanner::$scheduled = 200; wfConfig::$data['scanMonitorLastAttempt'] = 100; return null; }
}
require dirname( __DIR__ ) . '/mcp-abilities-wordfence.php';
mcp_register_wordfence_abilities();
function call_ability( $name, $input = array() ) { return $GLOBALS['abilities'][ 'wordfence/' . $name ]['execute_callback']( $input ); }
$failed = 0;
function check_result( $ok, $name ) { global $failed; echo ( $ok ? 'PASS: ' : 'FAIL: ' ) . $name . "\n"; if ( ! $ok ) { ++$failed; } }
check_result( 'disabled' === mcp_wordfence_get_firewall_mode(), 'Native disabled firewall mode overrides stale configuration' );
check_result( false === call_ability( 'block-ip', array( 'ip' => '192.0.2.12' ) )['success'], 'Failed native block creation is reported' );
wfBlock::$block = (object) array( 'id' => 1, 'expiration' => 0 );
check_result( false === call_ability( 'unblock-ip', array( 'ip' => '192.0.2.12' ) )['success'], 'Failed native unblock is reported' );
check_result( false === call_ability( 'unlock-ip', array( 'ip' => '192.0.2.12' ) )['success'], 'Failed native unlock is reported' );
check_result( false === call_ability( 'whitelist-ip', array( 'ip' => '192.0.2.12' ) )['success'], 'Unpersisted allowlist update is reported' );
check_result( false === call_ability( 'start-scan' )['verified'], 'An attempt and future schedule change do not prove a scan started' );
wfBlock::$block = (object) array( 'id' => 1, 'expiration' => time() + 60 );
check_result( false === call_ability( 'block-ip', array( 'ip' => '192.0.2.12', 'permanent' => true ) )['success'], 'Existing temporary block is not reported as permanent' );
wfBlock::$block = null; wfBlock::$create = true; wordfence::$write = true;
call_ability( 'whitelist-ip', array( 'ip' => '192.0.2.14' ) );
check_result( false === call_ability( 'block-ip', array( 'ip' => '192.0.2.14', 'permanent' => true ) )['success'] && null === wfBlock::$block, 'A newly stored allowlist entry prevents a same-request block' );
check_result( false === call_ability( 'list-live-traffic' )['success'], 'Traffic database error is not an empty successful report' );
check_result( false === call_ability( 'list-scan-issues' )['success'], 'Scan issue database error is reported' );
$GLOBALS['multisite'] = true;
check_result( false === $GLOBALS['abilities']['wordfence/get-status']['permission_callback'](), 'Network-wide Wordfence data requires network administration' );
exit( $failed ? 1 : 0 );
