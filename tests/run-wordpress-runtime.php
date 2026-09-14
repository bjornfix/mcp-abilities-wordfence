<?php
/** Run with wp eval-file on the authorised integration site. */
if ( ! class_exists( 'wordfence' ) || ! function_exists( 'wp_get_ability' ) ) {
 throw new RuntimeException( 'Active Wordfence and the Abilities API are required.' );
}
require_once ABSPATH . 'wp-admin/includes/plugin.php';
$plugin = get_plugin_data( WP_PLUGIN_DIR . '/mcp-abilities-wordfence/mcp-abilities-wordfence.php' );
if ( '1.0.15' !== $plugin['Version'] ) { throw new RuntimeException( 'The exact reviewed version is required.' ); }
$admins = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
if ( ! $admins ) { throw new RuntimeException( 'An administrator is required.' ); }
wp_set_current_user( (int) $admins[0] );
function wf_runtime_assert( $condition, $message ) {
 if ( ! $condition ) { throw new RuntimeException( $message ); }
 echo 'PASS: ' . $message . "\n";
}
function wf_runtime_call( $name, $input = array() ) {
 $ability = wp_get_ability( 'wordfence/' . $name );
 if ( ! $ability ) { throw new RuntimeException( 'Missing ability: ' . $name ); }
 $result = $ability->execute( $input );
 if ( is_wp_error( $result ) ) { throw new RuntimeException( $name . ': ' . $result->get_error_message() ); }
 return $result;
}
$ip = '203.0.113.241';
$allow = '203.0.113.242';
$original_allowlist = array_map( 'trim', explode( ',', (string) wfConfig::get( 'whitelisted', '', false ) ) );
if ( wfBlock::findIPBlock( $ip ) || wfBlock::lockoutForIP( $ip ) || wfBlock::isWhitelisted( $ip ) || in_array( $allow, $original_allowlist, true ) ) {
 throw new RuntimeException( 'The reserved fixture addresses are already in use.' );
}
$created_ids = array();
$allow_added = false;
try {
 $status = wf_runtime_call( 'get-status' );
 wf_runtime_assert( ! empty( $status['success'] ) && $status['firewall_mode'] === ( new wfFirewall() )->firewallMode(), 'Status matches native Wordfence firewall mode' );
 foreach ( array( 'get-scan-status', 'list-blocked-ips', 'list-live-traffic', 'list-scan-issues', 'list-lockouts' ) as $name ) {
  $result = wf_runtime_call( $name );
  wf_runtime_assert( ! empty( $result['success'] ), $name . ' returns native data' );
 }
 $result = wf_runtime_call( 'block-ip', array( 'ip' => $ip, 'reason' => 'Temporary integration fixture', 'permanent' => false ) );
 $block = wfBlock::findIPBlock( $ip );
 if ( $block ) { $created_ids[] = (int) $block->id; }
 wf_runtime_assert( ! empty( $result['success'] ) && $block && (int) $block->expiration > time(), 'Temporary block is stored with expiry' );
 $result = wf_runtime_call( 'block-ip', array( 'ip' => $ip, 'permanent' => true ) );
 wf_runtime_assert( empty( $result['success'] ) && (int) wfBlock::findIPBlock( $ip )->expiration > time(), 'Existing temporary block is preserved' );
 $result = wf_runtime_call( 'unblock-ip', array( 'ip' => $ip ) );
 wf_runtime_assert( ! empty( $result['success'] ) && ! wfBlock::findIPBlock( $ip ), 'Native block removal is verified' );
 $result = wf_runtime_call( 'block-ip', array( 'ip' => $ip, 'reason' => 'Permanent integration fixture', 'permanent' => true ) );
 $block = wfBlock::findIPBlock( $ip );
 if ( $block ) { $created_ids[] = (int) $block->id; }
 wf_runtime_assert( ! empty( $result['success'] ) && $block && 0 === (int) $block->expiration, 'Permanent block uses native zero expiry' );
 wf_runtime_call( 'unblock-ip', array( 'ip' => $ip ) );
 wfBlock::createLockout( 'Login integration fixture', $ip, 120 );
 $lockout = wfBlock::lockoutForIP( $ip );
 if ( $lockout ) { $created_ids[] = (int) $lockout->id; }
 wf_runtime_assert( (bool) $lockout, 'Native login-lockout fixture exists' );
 $result = wf_runtime_call( 'unlock-ip', array( 'ip' => $ip ) );
 wf_runtime_assert( ! empty( $result['success'] ) && ! wfBlock::lockoutForIP( $ip ), 'Login lockout is removed and verified' );
 $allow_added = true;
 $result = wf_runtime_call( 'whitelist-ip', array( 'ip' => $allow ) );
 wf_runtime_assert( ! empty( $result['success'] ) && in_array( $allow, explode( ',', wfConfig::get( 'whitelisted', '', false ) ), true ), 'Native allowlist entry is persisted' );
 $result = wf_runtime_call( 'block-ip', array( 'ip' => $allow, 'permanent' => true ) );
 wf_runtime_assert( empty( $result['success'] ) && ! wfBlock::findIPBlock( $allow ), 'Native allowlist prevents block and reports rejection' );
 wp_set_current_user( 0 );
 $denied = wp_get_ability( 'wordfence/get-status' )->execute( array() );
 wf_runtime_assert( is_wp_error( $denied ), 'Unauthenticated caller cannot read security data' );
} finally {
 wp_set_current_user( (int) $admins[0] );
 // Delete only records created by this fixture, never unrelated restrictions.
 if ( $created_ids ) { wfBlock::removeBlockIDs( $created_ids ); }
 if ( $allow_added ) {
  $current = array_map( 'trim', explode( ',', (string) wfConfig::get( 'whitelisted', '', false ) ) );
  wfConfig::set( 'whitelisted', implode( ',', array_values( array_filter( $current, static fn( $entry ) => $entry !== $allow ) ) ) );
 }
 wf_runtime_assert( ! wfBlock::findIPBlock( $ip ) && ! wfBlock::lockoutForIP( $ip ) && ! in_array( $allow, explode( ',', wfConfig::get( 'whitelisted', '', false ) ), true ), 'Temporary integration data is removed' );
}
