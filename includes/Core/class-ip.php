<?php
/**
 * Client IP resolution.
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
 * IP utilities.
 */
class SquidSec_Shield_IP {

	/**
	 * Best-effort client IP (proxy-aware, sanitized).
	 *
	 * @return string
	 */
	public static function remote_addr() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
	}

	public static function from_trusted_proxy() {
		$trusted = SquidSec_Shield_Options::get( 'trusted_proxies', array() );
		if ( ! is_array( $trusted ) || empty( $trusted ) ) {
			return false;
		}
		return self::in_list( self::remote_addr(), $trusted );
	}

	public static function client() {
		$remote = self::remote_addr();
		if ( ! self::from_trusted_proxy() ) {
			return $remote;
		}
		$headers = array(
			'HTTP_CF_CONNECTING_IP',
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED_FOR',
		);
		foreach ( $headers as $h ) {
			if ( empty( $_SERVER[ $h ] ) ) {
				continue;
			}
			$raw = sanitize_text_field( wp_unslash( $_SERVER[ $h ] ) );
			foreach ( explode( ',', $raw ) as $part ) {
				$part = trim( $part );
				if ( filter_var( $part, FILTER_VALIDATE_IP ) ) {
					return $part;
				}
			}
		}
		return $remote;
	}

	/**
	 * Is IP in list (exact or CIDR if provided as ip/mask).
	 *
	 * @param string $ip   IP.
	 * @param array  $list List of IPs/CIDRs.
	 * @return bool
	 */
	public static function in_list( $ip, array $list ) {
		foreach ( $list as $entry ) {
			$entry = trim( (string) $entry );
			if ( $entry === '' ) {
				continue;
			}
			if ( strpos( $entry, '/' ) !== false ) {
				if ( self::cidr_match( $ip, $entry ) ) {
					return true;
				}
			} elseif ( $ip === $entry ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CIDR match (IPv4).
	 *
	 * @param string $ip   IP.
	 * @param string $cidr CIDR.
	 * @return bool
	 */
	public static function cidr_match( $ip, $cidr ) {
		if ( strpos( $cidr, '/' ) === false ) {
			return $ip === $cidr;
		}
		list( $subnet, $mask ) = explode( '/', $cidr, 2 );
		$mask = (int) $mask;
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) && filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$ip_long  = ip2long( $ip );
			$sub_long = ip2long( $subnet );
			$mask_long = -1 << ( 32 - $mask );
			return ( $ip_long & $mask_long ) === ( $sub_long & $mask_long );
		}
		// Basic IPv6 exact only for now.
		return $ip === $subnet;
	}

	/**
	 * Is IP currently blocked in DB?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_blocked( $ip ) {
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'blocks' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id FROM {$table} WHERE ip = %s AND (permanent = 1 OR expires_at IS NULL OR expires_at > UTC_TIMESTAMP()) LIMIT 1",
				$ip
			)
		);
		return (bool) $row;
	}

	/**
	 * Block an IP temporarily or permanently.
	 *
	 * @param string $ip       IP.
	 * @param string $reason   Reason.
	 * @param int    $minutes  Duration (0 = permanent).
	 * @param string $rule_id  Rule.
	 * @param string $cve      CVE.
	 */
	public static function block( $ip, $reason = '', $minutes = 60, $rule_id = '', $cve = '' ) {
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'blocks' );
		$now   = gmdate( 'Y-m-d H:i:s' );
		$perm  = ( 0 === (int) $minutes ) ? 1 : 0;
		$exp   = $perm ? null : gmdate( 'Y-m-d H:i:s', time() + ( (int) $minutes * 60 ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$table,
			array(
				'created_at' => $now,
				'ip'         => $ip,
				'reason'     => substr( $reason, 0, 191 ),
				'rule_id'    => $rule_id,
				'cve'        => $cve,
				'expires_at' => $exp,
				'permanent'  => $perm,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%d' )
		);
	}
}
