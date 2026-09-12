<?php
/**
 * IP utilities tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_IP
 */
class IPTest extends SquidShield_TestCase {

	public function test_client_returns_ip_string() {
		$ip = SquidSec_Shield_IP::client();
		$this->assertIsString( $ip );
		$this->assertNotEmpty( $ip );
	}

	public function test_client_ignores_forwarded_headers_without_trusted_proxy() {
		$this->set_settings( array( 'trusted_proxies' => array() ) );
		$_SERVER['REMOTE_ADDR']             = '203.0.113.10';
		$_SERVER['HTTP_X_FORWARDED_FOR']    = '198.51.100.1';
		$_SERVER['HTTP_CF_CONNECTING_IP']   = '198.51.100.2';
		$_SERVER['HTTP_X_REAL_IP']          = '198.51.100.3';
		$this->assertSame( '203.0.113.10', SquidSec_Shield_IP::client() );
		$this->assertFalse( SquidSec_Shield_IP::from_trusted_proxy() );
	}

	public function test_client_uses_cf_header_from_trusted_proxy() {
		$this->set_settings( array( 'trusted_proxies' => array( '127.0.0.1', '10.0.0.0/8' ) ) );
		$_SERVER['REMOTE_ADDR']           = '10.0.0.5';
		$_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.20';
		$_SERVER['HTTP_X_FORWARDED_FOR']  = '198.51.100.21';
		$this->assertTrue( SquidSec_Shield_IP::from_trusted_proxy() );
		$this->assertSame( '198.51.100.20', SquidSec_Shield_IP::client() );
	}

	public function test_in_list_exact_match() {
		$this->assertTrue( SquidSec_Shield_IP::in_list( '1.2.3.4', array( '1.2.3.4', '5.6.7.8' ) ) );
		$this->assertFalse( SquidSec_Shield_IP::in_list( '1.2.3.4', array( '5.6.7.8' ) ) );
	}

	public function test_cidr_match_ipv4() {
		$this->assertTrue( SquidSec_Shield_IP::cidr_match( '192.168.1.50', '192.168.1.0/24' ) );
		$this->assertFalse( SquidSec_Shield_IP::cidr_match( '192.168.2.50', '192.168.1.0/24' ) );
		$this->assertTrue( SquidSec_Shield_IP::in_list( '10.0.0.8', array( '10.0.0.0/8' ) ) );
	}

	public function test_block_and_is_blocked() {
		$ip = '203.0.113.' . wp_rand( 1, 250 );
		// Ensure clean.
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'blocks' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE ip = %s", $ip ) );

		$this->assertFalse( SquidSec_Shield_IP::is_blocked( $ip ) );
		SquidSec_Shield_IP::block( $ip, 'unit-test', 5, 'test_rule', 'CVE-TEST' );
		$this->assertTrue( SquidSec_Shield_IP::is_blocked( $ip ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE ip = %s", $ip ) );
		$this->assertFalse( SquidSec_Shield_IP::is_blocked( $ip ) );
	}
}
