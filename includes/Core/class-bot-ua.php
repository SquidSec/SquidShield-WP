<?php
/**
 * User-Agent classification helpers (SEO allowlist, tool bots, scrapers).
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
 * Bot / crawler User-Agent helpers.
 */
class SquidSec_Shield_Bot_UA {

	/**
	 * Default SEO / social crawlers that should not be treated as hostile.
	 *
	 * @return string Newline-separated partial matches (lowercase intended).
	 */
	public static function default_good_user_agents() {
		return implode(
			"\n",
			array(
				'googlebot',
				'adsbot-google',
				'apis-google',
				'mediapartners-google',
				'google-inspectiontool',
				'storebot-google',
				'bingbot',
				'bingpreview',
				'adidxbot',
				'microsoftpreview',
				'applebot',
				'duckduckbot',
				'facebookexternalhit',
				'facebot',
				'meta-externalagent',
				'meta-externalfetcher',
				'slurp',
			)
		);
	}

	/**
	 * Default hostile / tool User-Agents (scrapers and scanners, not major SEO).
	 *
	 * @return string
	 */
	public static function default_bad_user_agents() {
		return implode(
			"\n",
			array(
				'curl/',
				'wget/',
				'ffuf',
				'wpscan',
				'libredtail',
				'python-requests',
				'python-urllib',
				'go-http-client',
				'httpie',
				'headlesschrome',
				'sqlmap',
				'nikto',
				'nmap',
				'masscan',
				'zgrab',
				'semrush',
				'ahrefs',
				'bytespider',
				'gptbot',
				'claudebot',
				'petalbot',
				'dotbot',
				'mj12bot',
				'proximic',
				'ia_archiver',
				'archive.org_bot',
				'scanner',
				'dirbuster',
				'dirb',
				'whatweb',
				'nessus',
				'openvas',
				'arachni',
				'w3af',
				'zaproxy',
				'burp',
				'nuclei',
				'httpx',
				'httprobe',
				'gobuster',
				'dirsearch',
				'feroxbuster',
				'katana',
				'hakrawler',
				'baiduspider',
				'yandex',
			)
		);
	}

	/**
	 * Default stealth-scraper UA fragments.
	 *
	 * @return string
	 */
	public static function default_scraper_user_agents() {
		return implode(
			"\n",
			array(
				'mozlila',
				'firefox/78.0',
			)
		);
	}

	/**
	 * Normalize UA for matching.
	 *
	 * @param string $ua Raw UA.
	 * @return string Lowercased trimmed UA.
	 */
	public static function normalize( $ua ) {
		return strtolower( trim( (string) $ua ) );
	}

	/**
	 * Whether UA matches any line in a newline list (substring, case-insensitive).
	 *
	 * @param string $ua   UA (any case).
	 * @param string $list Newline-separated needles.
	 * @return bool
	 */
	public static function matches_list( $ua, $list ) {
		$ua = self::normalize( $ua );
		if ( $ua === '' || ! is_string( $list ) || $list === '' ) {
			return false;
		}
		$lines = preg_split( '/\r?\n/', $list );
		foreach ( $lines as $entry ) {
			$entry = trim( strtolower( (string) $entry ) );
			if ( $entry === '' || strpos( $entry, '#' ) === 0 ) {
				continue;
			}
			if ( false !== strpos( $ua, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Known legitimate search / social crawler.
	 *
	 * @param string $ua UA.
	 * @return bool
	 */
	public static function is_good_ua( $ua ) {
		$list = SquidSec_Shield_Options::get( 'good_user_agents', self::default_good_user_agents() );
		return self::matches_list( $ua, is_string( $list ) ? $list : self::default_good_user_agents() );
	}

	/**
	 * Obvious hostile tool / unwanted bot UA (after good-UA allowlist).
	 *
	 * @param string $ua UA.
	 * @return bool
	 */
	public static function is_bad_ua( $ua ) {
		if ( self::is_good_ua( $ua ) ) {
			return false;
		}
		$list = SquidSec_Shield_Options::get( 'bad_user_agents', self::default_bad_user_agents() );
		return self::matches_list( $ua, is_string( $list ) ? $list : self::default_bad_user_agents() );
	}

	/**
	 * Stealth scraper / mass-crawler UA quirks (browser spoof, typos, empty).
	 *
	 * @param string $ua UA.
	 * @return bool
	 */
	public static function is_scraper_ua( $ua ) {
		if ( self::is_good_ua( $ua ) ) {
			return false;
		}

		$raw = trim( (string) $ua );
		$ua  = self::normalize( $raw );

		// Empty / placeholder UAs are almost never real browsers on HTML pages.
		if ( $ua === '' || $ua === '-' ) {
			return true;
		}

		// Bare Mozilla/5.0 with nothing else (common scraper).
		if ( $ua === 'mozilla/5.0' ) {
			return true;
		}

		// Very short non-tool tokens (e.g. "bot", "test") — keep tool UAs like curl/x for bad_ua.
		if ( strlen( $ua ) < 12 && false === strpos( $ua, '/' ) ) {
			return true;
		}

		// Common headless / automation leftovers.
		if ( false !== strpos( $ua, 'headless' ) || false !== strpos( $ua, 'phantomjs' ) || false !== strpos( $ua, 'selenium' ) ) {
			return true;
		}

		// Ancient Firefox/78 on X11 Linux is a common full-site scraper fingerprint.
		if ( false !== strpos( $ua, 'firefox/78.0' ) && false !== strpos( $ua, 'x11' ) && false !== strpos( $ua, 'linux' ) ) {
			return true;
		}

		$list = SquidSec_Shield_Options::get( 'scraper_user_agents', self::default_scraper_user_agents() );
		return self::matches_list( $ua, is_string( $list ) ? $list : self::default_scraper_user_agents() );
	}

	/**
	 * Broad bot detection for analytics (named bots + scrapers + tools).
	 *
	 * @param string $ua UA.
	 * @return bool
	 */
	public static function is_bot_ua( $ua ) {
		if ( self::is_good_ua( $ua ) ) {
			return true; // Still a bot for traffic stats, just not hostile.
		}
		if ( self::is_bad_ua( $ua ) || self::is_scraper_ua( $ua ) ) {
			return true;
		}
		$ua = self::normalize( $ua );
		return (bool) preg_match(
			'/bot|crawl|spider|slurp|preview|pingdom|gtmetrix|lighthouse|wget|curl|python-requests|scrapy|httpclient|okhttp|libwww|java\/|axios|bytespider|gptbot|claude|petalbot|semrush|ahrefs|yandex|baidu|mj12|dotbot|facebookexternal|meta-external|amazonbot|applebot|duckduck|ia_archiver|archive\.org|censys|shodan|nuclei|httpx|go-http/i',
			$ua
		);
	}
}
