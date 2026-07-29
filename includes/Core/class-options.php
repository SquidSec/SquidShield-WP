<?php
/**
 * Plugin settings store.
 *
 * @package SquidSec_Shield
 * @author            SquidSec
 * @copyright         2026 SquidSec
 * @license           GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Options helper.
 */
class SquidSec_Shield_Options {

	const OPTION_KEY = 'squidsec_shield_settings';

	/**
	 * Default settings.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			// General.
			'enabled'                 => true,
			'pentest_mode'            => false, // Log but do not block.
			'notify_email'            => '',
			'webhook_url'             => '',
			'slack_webhook'           => '',
			'daily_report'            => true,
			// WAF.
			'waf_enabled'             => true,
			'waf_block_sqli'          => true,
			'waf_block_xss'           => true,
			'waf_block_rce'           => true,
			'waf_block_lfi'           => true,
			'waf_block_upload'        => true,
			'virtual_patch_enabled'   => true,
			'rate_limit_enabled'      => true,
			'rate_limit_ajax'         => 120,
			'rate_limit_rest'         => 90,
			'rate_limit_login'        => 10,
			'rate_limit_xmlrpc'       => 20,
			'rate_limit_window'       => 60,
			'geo_block_enabled'       => false,
			'geo_block_countries'     => array(),
			'ip_blocklist'            => array(),
			'ip_allowlist'            => array(),
			// Auth.
			'login_protection'        => true,
			'login_max_attempts'      => 5,
			'login_lockout_minutes'   => 15,
			'login_lock_username'     => true,
			'hide_login_errors'       => true,
			'custom_login_slug'       => '',
			'disable_xmlrpc'          => true,
			'disable_xmlrpc_pingback' => true,
			'user_enum_prevention'    => true,
			'disable_author_archives' => true,
			// CAPTCHA / Turnstile.
			'captcha_provider'        => 'none', // none|recaptcha|turnstile.
			'captcha_site_key'        => '',
			'captcha_secret_key'      => '',
			'captcha_on_login'        => false,
			// 2FA.
			'totp_enabled'            => true,
			'totp_enforce_roles'      => array(), // empty = optional for all.
			'totp_grace_days'         => 7,
			// Scanners.
			'malware_scan_enabled'    => true,
			'malware_schedule'        => 'daily',
			'fim_enabled'             => true,
			'fim_schedule'            => 'hourly',
			'vuln_scan_enabled'       => true,
			'vuln_schedule'           => 'daily',
			'misconfig_scan_enabled'  => true,
			// Hardening.
			'hardening_file_editor'   => true,
			'hardening_hide_version'  => true,
			'hardening_headers'       => true,
			'hardening_disable_reg'   => false,
			'hardening_remove_wp_gen' => true,
			'hardening_disable_app_pass_nonadmin' => true,
			// Remove readme/license files that leak versions (core, plugins, themes).
			'remove_readme_license'   => true,
			// Sensitive files.
			'sensitive_file_protect'  => true,
			// Anomaly.
			'anomaly_detection'       => true,
			// Logging.
			'log_retention_days'      => 90,
			'log_blocked_payloads'    => true,
			// Performance.
			'async_scans'             => true,
			'scan_batch_size'         => 40,
			// Custom rules sandbox.
			'custom_rules_enabled'    => true,
			// New hardening features (from server-level lessons).
			'bad_user_agents_enabled' => true,
			// Hostile tools / scrapers only. Major SEO/social bots live in good_user_agents.
			'bad_user_agents'         => SquidSec_Shield_Bot_UA::default_bad_user_agents(),
			'probe_patterns_enabled'  => true,
			'admin_ip_protection'     => true,
			'admin_ip_allowlist'      => array(),
			'block_mode'              => 'soft', // soft = friendly block page, hard = plain 403
			'rate_limit_admin'        => 60,
			// Front-end rate limit (requests per window). 0 disables.
			'rate_limit_general'      => 90,
			// SEO / social crawlers never blocked as "bad UA" or scrapers.
			'good_user_agents'        => SquidSec_Shield_Bot_UA::default_good_user_agents(),
			// Stealth scraper UA quirks (browser spoof, empty UA, etc.).
			'scraper_ua_enabled'      => true,
			'scraper_user_agents'     => SquidSec_Shield_Bot_UA::default_scraper_user_agents(),
		);
	}

	/**
	 * Ensure option exists with defaults merged.
	 */
	public static function ensure_defaults() {
		$current = get_option( self::OPTION_KEY, null );
		if ( ! is_array( $current ) ) {
			update_option( self::OPTION_KEY, self::defaults(), false );
			return;
		}
		$merged = array_merge( self::defaults(), $current );
		if ( $merged !== $current ) {
			update_option( self::OPTION_KEY, $merged, false );
		}
	}

	/**
	 * Get all settings.
	 *
	 * @return array
	 */
	public static function all() {
		$opts = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $opts ) ) {
			$opts = array();
		}
		return array_merge( self::defaults(), $opts );
	}

	/**
	 * Get one setting.
	 *
	 * @param string $key     Key.
	 * @param mixed  $default Default.
	 * @return mixed
	 */
	public static function get( $key, $default = null ) {
		$all = self::all();
		if ( array_key_exists( $key, $all ) ) {
			return $all[ $key ];
		}
		return $default;
	}

	/**
	 * Update settings (partial).
	 *
	 * @param array $patch Partial settings.
	 * @return array
	 */
	public static function update( array $patch ) {
		$all = self::all();
		foreach ( $patch as $k => $v ) {
			if ( array_key_exists( $k, self::defaults() ) ) {
				$all[ $k ] = $v;
			}
		}
		update_option( self::OPTION_KEY, $all, false );
		return $all;
	}

	/**
	 * Is global protection on?
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return (bool) self::get( 'enabled', true );
	}

	/**
	 * Pentest mode (log only).
	 *
	 * @return bool
	 */
	public static function is_pentest() {
		return (bool) self::get( 'pentest_mode', false );
	}
}
