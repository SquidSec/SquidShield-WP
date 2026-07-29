<?php
/**
 * Tests for SEO allowlist, bad UA, and scraper UA classification.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Bot_UA
 */
class BotUaTest extends SquidShield_TestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->set_settings(
			array(
				'good_user_agents'    => SquidSec_Shield_Bot_UA::default_good_user_agents(),
				'bad_user_agents'     => SquidSec_Shield_Bot_UA::default_bad_user_agents(),
				'scraper_user_agents' => SquidSec_Shield_Bot_UA::default_scraper_user_agents(),
			)
		);
	}

	public function test_seo_good_uas_are_allowed() {
		$good = array(
			'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
			'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
			'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1)',
			'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)',
			'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)',
		);
		foreach ( $good as $ua ) {
			$this->assertTrue( SquidSec_Shield_Bot_UA::is_good_ua( $ua ), $ua );
			$this->assertFalse( SquidSec_Shield_Bot_UA::is_bad_ua( $ua ), 'good must win over bad: ' . $ua );
			$this->assertFalse( SquidSec_Shield_Bot_UA::is_scraper_ua( $ua ), 'good must not be scraper: ' . $ua );
		}
	}

	public function test_bingbot_not_bad_even_if_listed_in_bad() {
		$this->set_settings(
			array(
				'good_user_agents' => "bingbot\ngooglebot",
				'bad_user_agents'  => "bingbot\ncurl/",
			)
		);
		$ua = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_good_ua( $ua ) );
		$this->assertFalse( SquidSec_Shield_Bot_UA::is_bad_ua( $ua ) );
	}

	public function test_tool_uas_are_bad() {
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_bad_ua( 'curl/8.18.0' ) );
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_bad_ua( 'python-requests/2.31.0' ) );
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_bad_ua( 'Go-http-client/1.1' ) );
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_bad_ua( 'nuclei' ) );
		$this->assertFalse( SquidSec_Shield_Bot_UA::is_bad_ua( 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' ) );
	}

	public function test_scraper_quirks_detected() {
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_scraper_ua( '' ) );
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_scraper_ua( '-' ) );
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_scraper_ua( 'Mozilla/5.0' ) );
		$this->assertTrue(
			SquidSec_Shield_Bot_UA::is_scraper_ua(
				'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'
			)
		);
		$this->assertTrue(
			SquidSec_Shield_Bot_UA::is_scraper_ua(
				'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv)'
			)
		);
		$this->assertFalse(
			SquidSec_Shield_Bot_UA::is_scraper_ua(
				'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
			)
		);
	}

	public function test_is_bot_ua_for_analytics() {
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_bot_ua( 'Googlebot/2.1' ) );
		$this->assertTrue( SquidSec_Shield_Bot_UA::is_bot_ua( 'curl/8.0' ) );
		$this->assertTrue(
			SquidSec_Shield_Bot_UA::is_bot_ua(
				'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0'
			)
		);
		$this->assertFalse(
			SquidSec_Shield_Bot_UA::is_bot_ua(
				'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
			)
		);
	}

	public function test_rate_limit_general_default_enabled() {
		$d = SquidSec_Shield_Options::defaults();
		$this->assertGreaterThan( 0, (int) $d['rate_limit_general'] );
		$this->assertTrue( ! empty( $d['scraper_ua_enabled'] ) );
		$this->assertStringContainsString( 'googlebot', strtolower( $d['good_user_agents'] ) );
		$this->assertStringNotContainsString( 'bingbot', strtolower( $d['bad_user_agents'] ) );
		$this->assertStringNotContainsString( 'facebookexternalhit', strtolower( $d['bad_user_agents'] ) );
	}
}
