<?php
/**
 * Simple classmap autoloader for SquidSec Shield.
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
 * Autoloader.
 */
class SquidSec_Shield_Autoloader {

	/**
	 * Class map: class name => relative path under includes/.
	 *
	 * @var array
	 */
	private static $map = array(
		'SquidSec_Shield_Plugin'            => 'class-plugin.php',
		'SquidSec_Shield_Activator'         => 'class-activator.php',
		'SquidSec_Shield_Deactivator'       => 'class-deactivator.php',
		'SquidSec_Shield_Options'           => 'Core/class-options.php',
		'SquidSec_Shield_Database'          => 'Core/class-database.php',
		'SquidSec_Shield_IP'                => 'Core/class-ip.php',
		'SquidSec_Shield_Bot_UA'            => 'Core/class-bot-ua.php',
		'SquidSec_Shield_Helpers'           => 'Core/class-helpers.php',
		'SquidSec_Shield_Cron'              => 'Core/class-cron.php',
		'SquidSec_Shield_Setup'             => 'Core/class-setup.php',
		'SquidSec_Shield_WAF'               => 'WAF/class-waf.php',
		'SquidSec_Shield_Rules_Engine'      => 'WAF/class-rules-engine.php',
		'SquidSec_Shield_Virtual_Patch'     => 'WAF/class-virtual-patch.php',
		'SquidSec_Shield_Rate_Limit'        => 'WAF/class-rate-limit.php',
		'SquidSec_Shield_Malware_Scanner'   => 'Malware/class-scanner.php',
		'SquidSec_Shield_Signatures'        => 'Malware/class-signatures.php',
		'SquidSec_Shield_Remediation'       => 'Malware/class-remediation.php',
		'SquidSec_Shield_FIM'               => 'Malware/class-fim.php',
		'SquidSec_Shield_Login_Protection'  => 'Auth/class-login-protection.php',
		'SquidSec_Shield_User_Enumeration'  => 'Auth/class-user-enumeration.php',
		'SquidSec_Shield_Two_Factor'        => 'Auth/class-two-factor.php',
		'SquidSec_Shield_Captcha'           => 'Auth/class-captcha.php',
		'SquidSec_Shield_Vuln_Scanner'      => 'Vuln/class-vuln-scanner.php',
		'SquidSec_Shield_Plugin_Risk'       => 'Vuln/class-plugin-risk.php',
		'SquidSec_Shield_Hardening'         => 'Hardening/class-hardening.php',
		'SquidSec_Shield_Misconfig'         => 'Hardening/class-misconfig.php',
		'SquidSec_Shield_Sensitive_Files'   => 'Hardening/class-sensitive-files.php',
		'SquidSec_Shield_Fingerprint_Cleanup' => 'Hardening/class-fingerprint-cleanup.php',
		'SquidSec_Shield_Audit_Log'         => 'Logging/class-audit-log.php',
		'SquidSec_Shield_Alerts'            => 'Logging/class-alerts.php',
		'SquidSec_Shield_REST_API'          => 'API/class-rest-api.php',
		'SquidSec_Shield_Webhooks'          => 'API/class-webhooks.php',
		'SquidSec_Shield_Admin'             => 'Admin/class-admin.php',
		'SquidSec_Shield_Anomaly'           => 'Anomaly/class-anomaly.php',
	);

	/**
	 * Register autoloader.
	 */
	public static function register() {
		spl_autoload_register( array( __CLASS__, 'load' ) );
	}

	/**
	 * Load a class.
	 *
	 * @param string $class Class name.
	 */
	public static function load( $class ) {
		if ( ! isset( self::$map[ $class ] ) ) {
			return;
		}
		$file = SQUIDSEC_SHIELD_DIR . 'includes/' . self::$map[ $class ];
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
}
