<?php
/**
 * Options store tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Options
 */
class OptionsTest extends SquidShield_TestCase {

	public function test_defaults_enable_core_protection() {
		$d = SquidSec_Shield_Options::defaults();
		$this->assertTrue( $d['enabled'] );
		$this->assertFalse( $d['pentest_mode'] );
		$this->assertTrue( $d['waf_enabled'] );
		$this->assertTrue( $d['login_protection'] );
		$this->assertTrue( $d['user_enum_prevention'] );
		$this->assertTrue( $d['disable_xmlrpc'] );
		$this->assertTrue( $d['malware_scan_enabled'] );
		$this->assertTrue( $d['fim_enabled'] );
		$this->assertTrue( $d['remove_readme_license'] );
		$this->assertTrue( $d['virtual_patch_enabled'] );
		$this->assertTrue( $d['rate_limit_enabled'] );
		$this->assertSame( array(), $d['trusted_proxies'] );
	}

	public function test_update_merges_partial_patch() {
		$this->set_settings( array( 'login_max_attempts' => 7 ) );
		$this->assertSame( 7, (int) SquidSec_Shield_Options::get( 'login_max_attempts' ) );
		// Unrelated default remains.
		$this->assertTrue( (bool) SquidSec_Shield_Options::get( 'waf_enabled' ) );
	}

	public function test_is_enabled_and_pentest_helpers() {
		$this->set_settings( array( 'enabled' => true, 'pentest_mode' => false ) );
		$this->assertTrue( SquidSec_Shield_Options::is_enabled() );
		$this->assertFalse( SquidSec_Shield_Options::is_pentest() );

		$this->set_settings( array( 'pentest_mode' => true ) );
		$this->assertTrue( SquidSec_Shield_Options::is_pentest() );

		$this->set_settings( array( 'enabled' => false ) );
		$this->assertFalse( SquidSec_Shield_Options::is_enabled() );
	}

	public function test_update_ignores_unknown_keys() {
		$this->set_settings( array( 'not_a_real_key' => 'x' ) );
		$all = SquidSec_Shield_Options::all();
		$this->assertArrayNotHasKey( 'not_a_real_key', $all );
	}
}
