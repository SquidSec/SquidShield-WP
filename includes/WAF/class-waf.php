<?php
/**
 * WordPress-aware WAF.
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
 * WAF.
 */
class SquidSec_Shield_WAF {

	/**
	 * Whether this request was already evaluated.
	 *
	 * @var bool
	 */
	private static $ran = false;

	/**
	 * Register hooks.
	 */
	public static function init() {
		// Extra pass after REST/XMLRPC constants are known.
		add_action( 'init', array( __CLASS__, 'maybe_run' ), 0 );
		add_action( 'rest_api_init', array( __CLASS__, 'maybe_run' ), 0 );
		add_filter( 'xmlrpc_enabled', array( __CLASS__, 'filter_xmlrpc' ) );
	}

	/**
	 * Evaluate and possibly block.
	 */
	public static function maybe_run() {
		if ( self::$ran ) {
			return;
		}
		self::$ran = true;

		if ( ! SquidSec_Shield_Options::is_enabled() ) {
			return;
		}
		if ( ! SquidSec_Shield_Options::get( 'waf_enabled' ) ) {
			return;
		}

		// Never block CLI/cron internals.
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}
		if ( PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ) {
			return;
		}

		$ip = SquidSec_Shield_IP::client();

		// Allowlist always wins.
		$allow = SquidSec_Shield_Options::get( 'ip_allowlist', array() );
		if ( is_array( $allow ) && SquidSec_Shield_IP::in_list( $ip, $allow ) ) {
			return;
		}

		// Settings blocklist.
		$blocklist = SquidSec_Shield_Options::get( 'ip_blocklist', array() );
		if ( is_array( $blocklist ) && SquidSec_Shield_IP::in_list( $ip, $blocklist ) ) {
			self::block_response( 'ip_blocklist', 'IP on blocklist', '', $ip );
			return;
		}

		// Dynamic blocks.
		if ( SquidSec_Shield_IP::is_blocked( $ip ) ) {
			self::block_response( 'ip_temp_block', 'IP temporarily blocked', '', $ip );
			return;
		}

		// Geo block (optional; uses CF header if present).
		if ( SquidSec_Shield_Options::get( 'geo_block_enabled' ) ) {
			$blocked_countries = SquidSec_Shield_Options::get( 'geo_block_countries', array() );
			$cc = isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) ) : '';
			if ( $cc && is_array( $blocked_countries ) && in_array( $cc, $blocked_countries, true ) ) {
				self::block_response( 'geo_block', 'Country blocked: ' . $cc, '', $ip );
				return;
			}
		}

		$uri     = SquidSec_Shield_Helpers::request_uri();
		$payload = SquidSec_Shield_Helpers::request_payload();
		$context = SquidSec_Shield_Helpers::request_context();

		// Skip noisy internal admin assets for logged-in admins (reduce FPs).
		if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() && function_exists( 'current_user_can' ) && current_user_can( 'manage_options' ) ) {
			if ( in_array( $context, array( 'admin', 'ajax' ), true ) ) {
				// Still scan for clear RCE/upload attacks.
				$payload_check = $payload;
			}
		}

		// Logged-in admins skip UA hostility checks (still subject to attack rules below).
		$is_admin_user = function_exists( 'is_user_logged_in' ) && is_user_logged_in()
			&& function_exists( 'current_user_can' ) && current_user_can( 'manage_options' );

		$ua_raw = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		// SEO / social good bots: never block on UA alone.
		$is_good_bot = SquidSec_Shield_Bot_UA::is_good_ua( $ua_raw );

		// 1. Bad User-Agent blocking (tools/scanners). Good SEO UAs always win.
		if ( ! $is_admin_user && ! $is_good_bot && SquidSec_Shield_Options::get( 'bad_user_agents_enabled' ) ) {
			if ( SquidSec_Shield_Bot_UA::is_bad_ua( $ua_raw ) ) {
				self::block_response( 'bad_ua', 'Bad user agent', '', $ip );
				return;
			}
		}

		// 1b. Stealth scraper UA quirks (empty, bare Mozilla/5.0, FF78 mass-crawl, Mozlila, etc.).
		if ( ! $is_admin_user && ! $is_good_bot && SquidSec_Shield_Options::get( 'scraper_ua_enabled' ) ) {
			if ( SquidSec_Shield_Bot_UA::is_scraper_ua( $ua_raw ) ) {
				// Short temp block to stop full-site scrapers without permanent ban.
				SquidSec_Shield_IP::block( $ip, 'Scraper user agent', 60, 'scraper_ua', '' );
				self::block_response( 'scraper_ua', 'Scraper user agent', '', $ip );
				return;
			}
		}

		// 2. Common scanner / probe patterns (broad traversal, .env, wp-config, etc.)
		if ( SquidSec_Shield_Options::get( 'probe_patterns_enabled' ) ) {
			if ( self::matches_probe_pattern( $uri . ' ' . $payload ) ) {
				self::block_response( 'probe_pattern', 'Scanner probe pattern', '', $ip );
				return;
			}
		}

		// 3. Admin area IP protection (whitelist wp-admin / wp-login / admin-ajax)
		if ( SquidSec_Shield_Options::get( 'admin_ip_protection' ) ) {
			if ( self::is_admin_path( $uri ) ) {
				$admin_ips = SquidSec_Shield_Options::get( 'admin_ip_allowlist', array() );
				if ( is_array( $admin_ips ) && ! empty( $admin_ips ) ) {
					if ( ! SquidSec_Shield_IP::in_list( $ip, $admin_ips ) && $ip !== '127.0.0.1' ) {
						self::block_response( 'admin_ip', 'Admin area restricted', '', $ip );
						return;
					}
				}
			}
		}

		$match = SquidSec_Shield_Rules_Engine::evaluate( $uri, $payload, $context );
		if ( ! $match ) {
			return;
		}

		$rule_id  = $match['id'] ?? 'unknown';
		$cve      = $match['cve'] ?? '';
		$name     = $match['name'] ?? $rule_id;
		$action   = $match['action'] ?? 'block';
		$severity = $match['severity'] ?? 'high';

		$msg = sprintf( 'WAF matched rule %s (%s)', $rule_id, $name );
		if ( $cve ) {
			$msg .= ' [' . $cve . ']';
		}

		SquidSec_Shield_Audit_Log::write(
			'waf_match',
			$severity,
			$msg,
			array(
				'rule_id' => $rule_id,
				'cve'     => $cve,
				'action'  => $action,
				'context' => $context,
				'uri'     => $uri,
				'payload' => SquidSec_Shield_Options::get( 'log_blocked_payloads' ) ? substr( $payload, 0, 2000 ) : '',
			),
			$rule_id,
			$cve
		);

		if ( 'log' === $action || SquidSec_Shield_Options::is_pentest() ) {
			return;
		}

		if ( 'challenge' === $action ) {
			// Soft block: rate-limit aggressively.
			SquidSec_Shield_Rate_Limit::penalize( $ip, $context );
			return;
		}

		// Auto temp-block on critical (high blocks the request but avoids long lockouts from noisy probes).
		if ( 'critical' === strtolower( $severity ) ) {
			SquidSec_Shield_IP::block( $ip, $msg, 30, $rule_id, $cve );
		} elseif ( 'high' === strtolower( $severity ) ) {
			SquidSec_Shield_IP::block( $ip, $msg, 10, $rule_id, $cve );
		}

		self::block_response( $rule_id, $msg, $cve, $ip );
	}

	/**
	 * Check against configurable bad user-agents.
	 *
	 * @param string $ua User-Agent (any case).
	 * @return bool
	 */
	protected static function is_bad_ua( $ua ) {
		return SquidSec_Shield_Bot_UA::is_bad_ua( $ua );
	}

	/**
	 * Simple broad probe / traversal pattern matcher.
	 *
	 * @param string $blob URI + payload lowercased.
	 * @return bool
	 */
	protected static function matches_probe_pattern( $blob ) {
		$blob = strtolower( (string) $blob );

		$patterns = array(
			'.env',
			'wp-config',
			'../',
			'%2e%2e',
			'/etc/passwd',
			'/etc/shadow',
			'.git/',
			'phpunit',
			'eval-stdin',
			'alfa.php',
			'wso.php',
			'xmlrpc.php',
			'base64_decode',
			'gzinflate',
			'str_rot13',
		);

		foreach ( $patterns as $p ) {
			if ( false !== strpos( $blob, $p ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is this an admin area path we want to protect?
	 *
	 * @param string $uri Request URI.
	 * @return bool
	 */
	protected static function is_admin_path( $uri ) {
		$uri = strtolower( (string) $uri );
		if ( false !== strpos( $uri, '/wp-admin' ) ) {
			return true;
		}
		if ( false !== strpos( $uri, '/wp-login.php' ) ) {
			return true;
		}
		if ( false !== strpos( $uri, '/admin-ajax.php' ) && false !== strpos( $uri, 'wp-admin' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Send block response and exit.
	 *
	 * @param string $rule_id Rule.
	 * @param string $message Message.
	 * @param string $cve     CVE.
	 * @param string $ip      IP.
	 */
	public static function block_response( $rule_id, $message, $cve = '', $ip = '' ) {
		if ( SquidSec_Shield_Options::is_pentest() ) {
			return;
		}

		$mode   = SquidSec_Shield_Options::get( 'block_mode', 'soft' );
		$status = 403;

		if ( ! headers_sent() ) {
			status_header( $status );
			nocache_headers();
			header( 'X-SquidSec-Shield: blocked' );
			if ( $rule_id ) {
				header( 'X-SquidSec-Rule: ' . preg_replace( '/[^a-zA-Z0-9_\-.]/', '', $rule_id ) );
			}
		}

		if ( 'hard' === $mode ) {
			// Plain 403, no fancy page (better for scanners and some CDNs).
			if ( ! headers_sent() ) {
				header( 'Content-Type: text/plain; charset=utf-8' );
			}
			echo 'Forbidden';
			exit;
		}

		// Soft / friendly block page (default)
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/html; charset=utf-8' );
		}

		$ref = $cve ? (string) $cve : (string) $rule_id;
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>' . esc_html__( 'Request Blocked', 'squidsec-shield' ) . '</title>';
		echo '<style>body{font-family:system-ui,sans-serif;background:#0b1220;color:#e8eefc;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}';
		echo '.box{max-width:480px;padding:32px;border:1px solid #243049;border-radius:12px;background:#121a2b;text-align:center}';
		echo 'h1{font-size:1.25rem;margin:0 0 12px;color:#7dd3fc}p{color:#94a3b8;line-height:1.5;margin:0 0 8px}';
		echo '.ref{font-size:12px;color:#64748b;margin-top:16px}</style></head><body><div class="box">';
		echo '<h1>' . esc_html__( 'SquidShield', 'squidsec-shield' ) . '</h1>';
		echo '<p>' . esc_html__( 'Your request was blocked by the site security policy.', 'squidsec-shield' ) . '</p>';
		echo '<p class="ref">' . esc_html( sprintf( /* translators: %s: rule or CVE id */ __( 'Ref: %s', 'squidsec-shield' ), $ref ) ) . '</p>';
		echo '</div></body></html>';
		exit;
	}

	/**
	 * Disable XML-RPC when configured.
	 *
	 * @param bool $enabled Enabled.
	 * @return bool
	 */
	public static function filter_xmlrpc( $enabled ) {
		if ( SquidSec_Shield_Options::get( 'disable_xmlrpc' ) ) {
			return false;
		}
		return $enabled;
	}
}
