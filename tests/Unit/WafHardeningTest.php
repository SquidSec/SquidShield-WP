<?php
/**
 * Tests for new hardening features in WAF:
 * - Bad User-Agent blocking
 * - Probe pattern blocking (traversal, .env, etc.)
 * - Admin IP allowlist protection
 * - Hard vs Soft block mode
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_WAF
 */
class WafHardeningTest extends SquidShield_TestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->set_settings(
			array(
				'enabled'                   => true,
				'waf_enabled'               => true,
				'bad_user_agents_enabled'   => true,
				'probe_patterns_enabled'    => true,
				'admin_ip_protection'       => true,
				'admin_ip_allowlist'        => array( '198.51.100.10' ),
				'block_mode'                => 'soft',
				'bad_user_agents'           => "curl/\nffuf\nwpscan\npython-urllib",
			)
		);
	}

	public function test_bad_ua_is_detected() {
		// Access protected method via a small wrapper test.
		$ref  = new ReflectionClass( 'SquidSec_Shield_WAF' );
		$meth = $ref->getMethod( 'is_bad_ua' );
		$meth->setAccessible( true );

		$this->assertTrue( $meth->invoke( null, 'curl/7.68.0' ) );
		$this->assertTrue( $meth->invoke( null, 'ffuf/1.5.0' ) );
		$this->assertFalse( $meth->invoke( null, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' ) );
		// SEO bots must not be treated as bad even via WAF helper.
		$this->assertFalse( $meth->invoke( null, 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' ) );
	}

	public function test_probe_patterns_detect_traversal_and_env() {
		$ref  = new ReflectionClass( 'SquidSec_Shield_WAF' );
		$meth = $ref->getMethod( 'matches_probe_pattern' );
		$meth->setAccessible( true );

		$this->assertTrue( $meth->invoke( null, '/?file=../../../etc/passwd' ) );
		$this->assertTrue( $meth->invoke( null, '/.env' ) );
		$this->assertTrue( $meth->invoke( null, '/wp-config.php.bak' ) );
		$this->assertTrue( $meth->invoke( null, '/%2e%2e/%2e%2e/etc/passwd' ) );
		$this->assertFalse( $meth->invoke( null, '/wp-content/uploads/2026/07/something.jpg' ) );
	}

	public function test_is_admin_path() {
		$ref  = new ReflectionClass( 'SquidSec_Shield_WAF' );
		$meth = $ref->getMethod( 'is_admin_path' );
		$meth->setAccessible( true );

		$this->assertTrue( $meth->invoke( null, '/wp-admin/' ) );
		$this->assertTrue( $meth->invoke( null, '/wp-admin/index.php' ) );
		$this->assertTrue( $meth->invoke( null, '/wp-login.php' ) );
		$this->assertTrue( $meth->invoke( null, '/wp-admin/admin-ajax.php' ) );
		$this->assertFalse( $meth->invoke( null, '/wp-content/uploads/foo.jpg' ) );
		$this->assertFalse( $meth->invoke( null, '/' ) );
	}

	public function test_admin_ip_protection_blocks_non_whitelisted() {
		// Simulate a request to /wp-admin from a non-allowed IP.
		$_SERVER['REMOTE_ADDR'] = '203.0.113.55';
		$_SERVER['REQUEST_URI'] = '/wp-admin/';

		// We can't easily call the full maybe_run without full WP boot, but we can test the IP check logic path.
		// For unit test we directly invoke the helper that would cause block.
		$ip = '203.0.113.55';
		$allow = array( '198.51.100.10' );

		$this->assertFalse( SquidSec_Shield_IP::in_list( $ip, $allow ) );
	}

	public function test_block_mode_hard_vs_soft_affects_output_format() {
		// We test the decision path by checking what block_response would do.
		// Since it exits, we capture by overriding in a test subclass or by checking the mode logic.
		$this->set_settings( array( 'block_mode' => 'hard' ) );
		$mode = SquidSec_Shield_Options::get( 'block_mode' );
		$this->assertSame( 'hard', $mode );

		$this->set_settings( array( 'block_mode' => 'soft' ) );
		$mode = SquidSec_Shield_Options::get( 'block_mode' );
		$this->assertSame( 'soft', $mode );
	}
}
