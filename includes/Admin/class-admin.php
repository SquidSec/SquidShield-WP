<?php
/**
 * Admin UI — dashboard and module pages.
 *
 * SquidSec Shield uses its own top-level menu so it is clearly separate
 * from site-specific SquidSec plugins (SMTP, Traffic, Popup, etc.).
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
 * Admin.
 */
class SquidSec_Shield_Admin {

	const SLUG = 'squidsec-shield';

	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 9 );
		add_action( 'admin_init', array( __CLASS__, 'handle_actions' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_filter( 'plugin_action_links_' . SQUIDSEC_SHIELD_BASENAME, array( __CLASS__, 'action_links' ) );
		// Label the other SquidSec hub so the split is obvious in the sidebar.
		add_action( 'admin_menu', array( __CLASS__, 'relabel_site_hub' ), 999 );
		// WordPress main Dashboard card.
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'register_dashboard_widget' ) );
	}

	/**
	 * Rename the site-ops SquidSec hub menu so it does not look like Shield.
	 */
	public static function relabel_site_hub() {
		global $menu, $submenu;
		if ( ! is_array( $menu ) ) {
			return;
		}
		foreach ( $menu as $idx => $item ) {
			if ( isset( $item[2] ) && 'squidsec' === $item[2] ) {
				// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				$menu[ $idx ][0] = 'SquidSec Site Tools';
				if ( isset( $menu[ $idx ][3] ) ) {
					// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
					$menu[ $idx ][3] = 'SquidSec Site Tools';
				}
			}
		}
		if ( isset( $submenu['squidsec'][0][0] ) ) {
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			$submenu['squidsec'][0][0] = 'Site overview';
		}
	}

	/**
	 * Plugin list links.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public static function action_links( $links ) {
		$url = admin_url( 'admin.php?page=' . self::SLUG );
		array_unshift( $links, '<a href="' . esc_url( $url ) . '"><strong>Open Shield</strong></a>' );
		return $links;
	}

	/**
	 * Assets.
	 *
	 * @param string $hook Hook.
	 */
	public static function assets( $hook ) {
		$on_plugin = ( false !== strpos( (string) $hook, self::SLUG ) || false !== strpos( (string) $hook, 'squidsec-shield' ) );
		$on_dash   = ( 'index.php' === $hook );
		if ( ! $on_plugin && ! $on_dash ) {
			return;
		}
		wp_enqueue_style( 'squidsec-shield-admin', SQUIDSEC_SHIELD_URL . 'assets/css/admin.css', array(), SQUIDSEC_SHIELD_VERSION );
		if ( $on_plugin ) {
			wp_enqueue_script( 'squidsec-shield-admin', SQUIDSEC_SHIELD_URL . 'assets/js/admin.js', array( 'jquery' ), SQUIDSEC_SHIELD_VERSION, true );
		}
	}

	/**
	 * Register the WP Dashboard widget.
	 */
	public static function register_dashboard_widget() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		wp_add_dashboard_widget(
			'squidshield_wp_dashboard',
			SQUIDSEC_SHIELD_NAME,
			array( __CLASS__, 'render_dashboard_widget' ),
			null,
			null,
			'normal',
			'high'
		);

		// Move to the top of the normal column when possible.
		global $wp_meta_boxes;
		if ( empty( $wp_meta_boxes['dashboard']['normal']['core']['squidshield_wp_dashboard'] ) ) {
			return;
		}
		$widget = $wp_meta_boxes['dashboard']['normal']['core']['squidshield_wp_dashboard'];
		unset( $wp_meta_boxes['dashboard']['normal']['core']['squidshield_wp_dashboard'] );
		$wp_meta_boxes['dashboard']['normal']['high']['squidshield_wp_dashboard'] = $widget;
	}

	/**
	 * Render WP Dashboard card.
	 */
	public static function render_dashboard_widget() {
		$status  = SquidSec_Shield_Setup::overall_status();
		$layers  = SquidSec_Shield_Setup::protection_layers();
		$on      = 0;
		$total   = count( $layers );
		foreach ( $layers as $layer ) {
			if ( ! empty( $layer['ok'] ) ) {
				$on++;
			}
		}
		$pct     = $total > 0 ? (int) round( ( $on / $total ) * 100 ) : 0;
		$sens    = get_option( 'squidsec_shield_sensitive_cache', array() );
		$misc    = get_option( 'squidsec_shield_misconfig_cache', array() );
		$issue_n = count( $sens['files'] ?? array() );
		foreach ( $misc['findings'] ?? array() as $f ) {
			if ( ! empty( $f['remediable'] ) ) {
				$issue_n++;
			}
		}
		$logs     = SquidSec_Shield_Audit_Log::query( array( 'limit' => 4 ) );
		$logo_url = SQUIDSEC_SHIELD_URL . 'assets/images/squidshield-logo.png';
		$logo_2x  = SQUIDSEC_SHIELD_URL . 'assets/images/squidshield-logo-2x.png';
		$open_url = admin_url( 'admin.php?page=' . self::SLUG );
		$fix_url  = admin_url( 'admin.php?page=squidsec-shield-hardening' );
		$act_url  = admin_url( 'admin.php?page=squidsec-shield-logs' );
		$level    = $status['level'] ?? 'ok';
		?>
		<div class="sss-wp-dash sss-wp-dash-<?php echo esc_attr( $level ); ?>">
			<div class="sss-wp-dash-top">
				<img class="sss-wp-dash-logo" src="<?php echo esc_url( $logo_url ); ?>" srcset="<?php echo esc_url( $logo_url ); ?> 1x, <?php echo esc_url( $logo_2x ); ?> 2x" width="40" height="48" alt="" />
				<div class="sss-wp-dash-head">
					<div class="sss-wp-dash-title-row">
						<strong class="sss-wp-dash-title"><?php echo esc_html( SQUIDSEC_SHIELD_NAME ); ?></strong>
						<span class="sss-wp-dash-ver">v<?php echo esc_html( SQUIDSEC_SHIELD_VERSION ); ?></span>
					</div>
					<p class="sss-wp-dash-status"><?php echo esc_html( $status['title'] ); ?></p>
					<p class="sss-wp-dash-msg"><?php echo esc_html( $status['message'] ); ?></p>
				</div>
				<div class="sss-wp-dash-meter" style="--sss-pct: <?php echo (int) $pct; ?>" aria-hidden="true">
					<span><?php echo (int) $pct; ?>%</span>
				</div>
			</div>

			<div class="sss-wp-dash-stats">
				<div class="sss-wp-dash-stat">
					<strong><?php echo (int) $on; ?>/<?php echo (int) $total; ?></strong>
					<span><?php esc_html_e( 'Protections on', 'squidsec-shield' ); ?></span>
				</div>
				<div class="sss-wp-dash-stat">
					<strong><?php echo (int) $issue_n; ?></strong>
					<span><?php esc_html_e( 'Issues to review', 'squidsec-shield' ); ?></span>
				</div>
				<div class="sss-wp-dash-stat">
					<strong><?php echo (int) count( $logs ); ?></strong>
					<span><?php esc_html_e( 'Recent events', 'squidsec-shield' ); ?></span>
				</div>
			</div>

			<?php if ( $layers ) : ?>
			<ul class="sss-wp-dash-layers">
				<?php foreach ( array_slice( $layers, 0, 6 ) as $layer ) : ?>
					<li class="<?php echo ! empty( $layer['ok'] ) ? 'is-on' : 'is-off'; ?>">
						<span class="sss-wp-dash-dot" aria-hidden="true"></span>
						<span class="sss-wp-dash-layer-label"><?php echo esc_html( $layer['label'] ); ?></span>
						<span class="sss-wp-dash-layer-state"><?php echo ! empty( $layer['ok'] ) ? esc_html__( 'On', 'squidsec-shield' ) : esc_html__( 'Off', 'squidsec-shield' ); ?></span>
					</li>
				<?php endforeach; ?>
			</ul>
			<?php if ( $total > 6 ) : ?>
				<p class="sss-wp-dash-more"><?php echo esc_html( sprintf( /* translators: %d: remaining */ __( '+ %d more protections', 'squidsec-shield' ), $total - 6 ) ); ?></p>
			<?php endif; ?>
			<?php endif; ?>

			<?php if ( $logs ) : ?>
			<div class="sss-wp-dash-activity">
				<div class="sss-wp-dash-activity-label"><?php esc_html_e( 'Latest activity', 'squidsec-shield' ); ?></div>
				<ul>
					<?php foreach ( $logs as $row ) : ?>
						<li>
							<span class="sss-wp-dash-time"><?php echo esc_html( $row['created_at'] ); ?></span>
							<span><?php echo esc_html( self::human_event_label( $row['event_type'], $row['message'] ) ); ?></span>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
			<?php endif; ?>

			<div class="sss-wp-dash-actions">
				<a class="button button-primary" href="<?php echo esc_url( $open_url ); ?>"><?php esc_html_e( 'Open SquidShield', 'squidsec-shield' ); ?></a>
				<?php if ( $issue_n > 0 ) : ?>
					<a class="button" href="<?php echo esc_url( $fix_url ); ?>"><?php echo esc_html( sprintf( /* translators: %d: count */ __( 'Fix %d issue(s)', 'squidsec-shield' ), $issue_n ) ); ?></a>
				<?php else : ?>
					<a class="button" href="<?php echo esc_url( $act_url ); ?>"><?php esc_html_e( 'View activity', 'squidsec-shield' ); ?></a>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Own top-level menu — not nested under site SquidSec tools.
	 */
	public static function menu() {
		add_menu_page(
			SQUIDSEC_SHIELD_NAME,
			'SquidShield',
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'page_dashboard' ),
			'dashicons-shield',
			2 // Above the site tools menu (position 3).
		);

		// Everyday labels first; technical tools still available under clearer names.
		$pages = array(
			self::SLUG                   => array( 'Dashboard', 'page_dashboard' ),
			'squidsec-shield-hardening'   => array( 'Issues to fix', 'page_hardening' ),
			'squidsec-shield-logs'        => array( 'Activity', 'page_logs' ),
			'squidsec-shield-settings'    => array( 'Settings', 'page_settings' ),
			'squidsec-shield-waf'         => array( 'Firewall', 'page_waf' ),
			'squidsec-shield-malware'     => array( 'Scanners', 'page_malware' ),
			'squidsec-shield-auth'        => array( 'Login security', 'page_auth' ),
			'squidsec-shield-vuln'        => array( 'Plugin risks', 'page_vuln' ),
			'squidsec-shield-api'         => array( 'Developers', 'page_api' ),
		);

		// First entry replaces the duplicate auto-created submenu title.
		foreach ( $pages as $slug => $meta ) {
			add_submenu_page(
				self::SLUG,
				SQUIDSEC_SHIELD_NAME . ' — ' . $meta[0],
				$meta[0],
				'manage_options',
				$slug,
				array( __CLASS__, $meta[1] )
			);
		}
	}

	/**
	 * Handle POST actions.
	 */
	public static function handle_actions() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_POST['sss_action'] ) ) {
			return;
		}
		check_admin_referer( 'sss_admin' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$action = sanitize_text_field( wp_unslash( $_POST['sss_action'] ) );

		switch ( $action ) {
			case 'save_settings':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$raw   = isset( $_POST['sss'] ) && is_array( $_POST['sss'] ) ? wp_unslash( $_POST['sss'] ) : array();
				$patch = self::normalize_settings_post( $raw );
				SquidSec_Shield_Options::update( $patch );
				add_settings_error( 'sss', 'saved', 'Settings saved.', 'updated' );
				break;
			case 'scan_malware':
				SquidSec_Shield_Malware_Scanner::start_scan( 'manual' );
				add_settings_error( 'sss', 'scan', 'Malware scan started. Large sites process in the background — refresh this page in a minute.', 'updated' );
				break;
			case 'scan_vuln':
				SquidSec_Shield_Vuln_Scanner::run_scan();
				add_settings_error( 'sss', 'vuln', 'Vulnerability scan complete. Review the findings table below.', 'updated' );
				break;
			case 'scan_misconfig':
				SquidSec_Shield_Misconfig::run_scan();
				SquidSec_Shield_Sensitive_Files::scan();
				add_settings_error( 'sss', 'misc', 'Misconfiguration & sensitive file scan complete.', 'updated' );
				break;
			case 'fim_baseline':
				SquidSec_Shield_FIM::create_baseline();
				add_settings_error( 'sss', 'fim', 'FIM baseline recreated. Future checks compare against this snapshot.', 'updated' );
				break;
			case 'fim_check':
				$c = SquidSec_Shield_FIM::check_integrity();
				add_settings_error( 'sss', 'fimc', 'FIM check complete: ' . count( $c ) . ' change(s) detected.', 'updated' );
				break;
			case 'hardening':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$profile = isset( $_POST['profile'] ) ? sanitize_text_field( wp_unslash( $_POST['profile'] ) ) : 'default';
				SquidSec_Shield_Hardening::apply_wizard( $profile );
				add_settings_error( 'sss', 'hard', 'Hardening profile applied: ' . $profile . '. You can reverse individual options under Settings / Auth / WAF.', 'updated' );
				break;
			case 'protect_uploads':
				$r = SquidSec_Shield_Sensitive_Files::apply_uploads_htaccess();
				if ( is_wp_error( $r ) ) {
					add_settings_error( 'sss', 'up', $r->get_error_message(), 'error' );
				} else {
					add_settings_error( 'sss', 'up', 'Uploads directory protection applied (.htaccess + index.php).', 'updated' );
				}
				break;
			case 'toggle_rule':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$rid = isset( $_POST['rule_id'] ) ? sanitize_text_field( wp_unslash( $_POST['rule_id'] ) ) : '';
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$en = ! empty( $_POST['enabled'] );
				if ( $rid ) {
					SquidSec_Shield_Rules_Engine::set_rule_enabled( $rid, $en );
					add_settings_error( 'sss', 'rule', 'Rule updated: ' . $rid, 'updated' );
				}
				break;
			case 'add_custom_rule':
				self::handle_add_custom_rule();
				break;
			case 'quarantine':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$sensitive = ! empty( $_POST['sensitive'] );
				$r         = SquidSec_Shield_Remediation::quarantine( $path, $sensitive );
				if ( ! is_wp_error( $r ) && $sensitive ) {
					SquidSec_Shield_Sensitive_Files::scan( true );
					SquidSec_Shield_Misconfig::run_scan( true );
				}
				add_settings_error( 'sss', 'q', is_wp_error( $r ) ? $r->get_error_message() : 'File quarantined under uploads/squidsec-shield-quarantine/.', is_wp_error( $r ) ? 'error' : 'updated' );
				break;
			case 'delete_file':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$sensitive = ! empty( $_POST['sensitive'] );
				$r         = SquidSec_Shield_Remediation::delete_file( $path, $sensitive || SquidSec_Shield_Remediation::is_remediable_sensitive_file( $path ) );
				if ( ! is_wp_error( $r ) ) {
					SquidSec_Shield_Sensitive_Files::scan( true );
					SquidSec_Shield_Misconfig::run_scan( true );
				}
				add_settings_error( 'sss', 'del', is_wp_error( $r ) ? $r->get_error_message() : 'Deleted: ' . $path, is_wp_error( $r ) ? 'error' : 'updated' );
				break;
			case 'remediate_all_sensitive':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$mode = isset( $_POST['mode'] ) ? sanitize_text_field( wp_unslash( $_POST['mode'] ) ) : 'delete';
				if ( ! in_array( $mode, array( 'delete', 'quarantine' ), true ) ) {
					$mode = 'delete';
				}
				$result = SquidSec_Shield_Remediation::remediate_all_sensitive( $mode );
				$msg    = sprintf(
					'Sensitive files: %d remediated, %d failed.',
					count( $result['ok'] ),
					count( $result['fail'] )
				);
				if ( ! empty( $result['ok'] ) ) {
					$msg .= ' Removed: ' . implode( ', ', array_slice( $result['ok'], 0, 12 ) );
					if ( count( $result['ok'] ) > 12 ) {
						$msg .= '…';
					}
				}
				if ( ! empty( $result['fail'] ) ) {
					$first = $result['fail'][0];
					$msg  .= ' First error: ' . ( $first['path'] ?? '' ) . ' — ' . ( $first['error'] ?? '' );
				}
				add_settings_error( 'sss', 'sens_all', $msg, empty( $result['fail'] ) ? 'updated' : 'warning' );
				break;
			case 'fix_misconfig':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$id = isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : '';
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
				$r    = SquidSec_Shield_Remediation::fix_misconfig( $id, $path );
				if ( ! is_wp_error( $r ) ) {
					SquidSec_Shield_Misconfig::run_scan( true );
					SquidSec_Shield_Sensitive_Files::scan( true );
				}
				add_settings_error( 'sss', 'mfix', is_wp_error( $r ) ? $r->get_error_message() : 'Fixed: ' . $id . ( $path ? ' (' . $path . ')' : '' ), is_wp_error( $r ) ? 'error' : 'updated' );
				break;
			case 'fix_all_findings':
				$result = SquidSec_Shield_Remediation::fix_all_auto_misconfigs();
				$fps    = SquidSec_Shield_Fingerprint_Cleanup::cleanup_all( true );
				$msg    = sprintf(
					'Auto-remediation complete: %d fixed, %d skipped/failed.',
					count( $result['ok'] ),
					count( $result['fail'] )
				);
				if ( ! empty( $result['ok'] ) ) {
					$msg .= ' ' . implode( ', ', array_slice( $result['ok'], 0, 15 ) );
				}
				if ( $fps ) {
					$msg .= ' Also removed ' . count( $fps ) . ' readme/license file(s).';
				}
				add_settings_error( 'sss', 'fix_all', $msg, 'updated' );
				break;
			case 'cleanup_fingerprints':
				$fps = SquidSec_Shield_Fingerprint_Cleanup::cleanup_all( true );
				add_settings_error(
					'sss',
					'fps',
					$fps
						? sprintf( 'Removed %d readme/license file(s) that leak version info.', count( $fps ) )
						: 'No public readme/license files found (already clean).',
					'updated'
				);
				break;
			case 'export_logs':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$fmt  = isset( $_POST['format'] ) ? sanitize_text_field( wp_unslash( $_POST['format'] ) ) : 'json';
				$data = SquidSec_Shield_Audit_Log::export( $fmt, 2000 );
				nocache_headers();
				header( 'Content-Type: ' . ( 'csv' === $fmt ? 'text/csv' : 'application/json' ) );
				header( 'Content-Disposition: attachment; filename=squidsec-shield-logs.' . $fmt );
				echo $data; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				exit;
			case 'block_ip':
				// phpcs:ignore WordPress.Security.NonceVerification.Missing
				$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					SquidSec_Shield_IP::block( $ip, 'Manual block', 0, 'manual' );
					add_settings_error( 'sss', 'ip', 'IP permanently blocked: ' . $ip, 'updated' );
				} else {
					add_settings_error( 'sss', 'ip', 'Invalid IP address.', 'error' );
				}
				break;
		}
	}

	/**
	 * Normalize settings POST (partial forms safe).
	 *
	 * @param array $raw Raw.
	 * @return array
	 */
	private static function normalize_settings_post( array $raw ) {
		$bools = array(
			'enabled', 'pentest_mode', 'waf_enabled', 'waf_block_sqli', 'waf_block_xss', 'waf_block_rce',
			'waf_block_lfi', 'waf_block_upload', 'virtual_patch_enabled', 'rate_limit_enabled',
			'geo_block_enabled', 'login_protection', 'login_lock_username', 'hide_login_errors',
			'disable_xmlrpc', 'disable_xmlrpc_pingback', 'user_enum_prevention', 'disable_author_archives',
			'captcha_on_login', 'totp_enabled', 'malware_scan_enabled', 'fim_enabled', 'vuln_scan_enabled',
			'misconfig_scan_enabled', 'hardening_file_editor', 'hardening_hide_version', 'hardening_headers',
			'hardening_disable_reg', 'hardening_remove_wp_gen', 'hardening_disable_app_pass_nonadmin',
			'remove_readme_license', 'sensitive_file_protect', 'anomaly_detection', 'log_blocked_payloads',
			'async_scans', 'custom_rules_enabled', 'daily_report',
			// New hardening options
			'bad_user_agents_enabled', 'probe_patterns_enabled', 'admin_ip_protection',
			'scraper_ua_enabled',
		);
		$out = array();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$bool_fields = isset( $_POST['sss_bools'] ) && is_array( $_POST['sss_bools'] )
			? array_map( 'sanitize_text_field', wp_unslash( $_POST['sss_bools'] ) )
			: array();
		foreach ( $bool_fields as $key ) {
			if ( in_array( $key, $bools, true ) ) {
				$out[ $key ] = ! empty( $raw[ $key ] );
			}
		}

		foreach ( SquidSec_Shield_Options::defaults() as $key => $default ) {
			if ( in_array( $key, $bools, true ) ) {
				continue;
			}
			if ( ! array_key_exists( $key, $raw ) ) {
				continue;
			}
			$val = $raw[ $key ];
			if ( in_array( $key, array( 'ip_blocklist', 'ip_allowlist', 'geo_block_countries', 'totp_enforce_roles', 'admin_ip_allowlist' ), true ) ) {
				if ( is_string( $val ) ) {
					$parts       = preg_split( '/[\s,]+/', $val );
					$out[ $key ] = array_values( array_filter( array_map( 'trim', $parts ) ) );
				} elseif ( is_array( $val ) ) {
					$out[ $key ] = array_values( array_filter( array_map( 'sanitize_text_field', $val ) ) );
				}
				continue;
			}
			if ( is_int( $default ) ) {
				$out[ $key ] = (int) $val;
			} elseif ( in_array( $key, array( 'bad_user_agents', 'good_user_agents', 'scraper_user_agents' ), true ) ) {
				// Multiline UA list — preserve newlines.
				$out[ $key ] = sanitize_textarea_field( (string) $val );
			} else {
				$out[ $key ] = sanitize_text_field( (string) $val );
			}
		}
		return $out;
	}

	/**
	 * Hidden markers for boolean fields on a form.
	 *
	 * @param array $keys Bool option keys.
	 */
	private static function bool_fields( array $keys ) {
		foreach ( $keys as $key ) {
			echo '<input type="hidden" name="sss_bools[]" value="' . esc_attr( $key ) . '" />';
		}
	}

	/**
	 * Toggle row with help text.
	 *
	 * @param string $key     Option key.
	 * @param string $label   Label.
	 * @param string $help    Help text.
	 * @param array  $opts    Options.
	 * @param string $warn    Optional warning note.
	 */
	private static function toggle( $key, $label, $help, array $opts, $warn = '' ) {
		?>
		<div class="sss-field">
			<div class="sss-toggle-row">
				<label for="sss-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label ); ?></label>
				<input type="checkbox" id="sss-<?php echo esc_attr( $key ); ?>" name="sss[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( ! empty( $opts[ $key ] ) ); ?> />
			</div>
			<p class="sss-help"><?php echo esc_html( $help ); ?></p>
			<?php if ( $warn ) : ?>
				<p class="sss-help sss-help-warn"><?php echo esc_html( $warn ); ?></p>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Text/number field with help.
	 *
	 * @param string $key     Key.
	 * @param string $label   Label.
	 * @param string $help    Help.
	 * @param mixed  $value   Value.
	 * @param string $type    input type.
	 * @param array  $attrs   Extra attrs (min, max, class, placeholder).
	 */
	private static function field( $key, $label, $help, $value, $type = 'text', array $attrs = array() ) {
		$class = $attrs['class'] ?? 'regular-text';
		$min   = isset( $attrs['min'] ) ? ' min="' . esc_attr( $attrs['min'] ) . '"' : '';
		$max   = isset( $attrs['max'] ) ? ' max="' . esc_attr( $attrs['max'] ) . '"' : '';
		$ph    = isset( $attrs['placeholder'] ) ? ' placeholder="' . esc_attr( $attrs['placeholder'] ) . '"' : '';
		$auto  = isset( $attrs['autocomplete'] ) ? ' autocomplete="' . esc_attr( $attrs['autocomplete'] ) . '"' : '';
		$rows  = isset( $attrs['rows'] ) ? (int) $attrs['rows'] : 4;
		?>
		<div class="sss-field">
			<label class="sss-field-label" for="sss-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $label ); ?></label>
			<?php if ( 'textarea' === $type ) : ?>
				<textarea id="sss-<?php echo esc_attr( $key ); ?>" class="<?php echo esc_attr( $class ); ?>" name="sss[<?php echo esc_attr( $key ); ?>]" rows="<?php echo esc_attr( (string) $rows ); ?>"<?php echo $ph; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>><?php echo esc_textarea( (string) $value ); ?></textarea>
			<?php else : ?>
				<input type="<?php echo esc_attr( $type ); ?>" id="sss-<?php echo esc_attr( $key ); ?>" class="<?php echo esc_attr( $class ); ?>" name="sss[<?php echo esc_attr( $key ); ?>]" value="<?php echo esc_attr( (string) $value ); ?>"<?php echo $min . $max . $ph . $auto; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?> />
			<?php endif; ?>
			<p class="sss-help"><?php echo esc_html( $help ); ?></p>
		</div>
		<?php
	}

	/**
	 * Add custom rule.
	 */
	private static function handle_add_custom_rule() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$name = isset( $_POST['rule_name'] ) ? sanitize_text_field( wp_unslash( $_POST['rule_name'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$pattern = isset( $_POST['rule_pattern'] ) ? wp_unslash( $_POST['rule_pattern'] ) : '';
		$pattern = is_string( $pattern ) ? trim( $pattern ) : '';
		$check   = SquidSec_Shield_Rules_Engine::sandbox_validate_pattern( $pattern );
		if ( is_wp_error( $check ) ) {
			add_settings_error( 'sss', 'cr', $check->get_error_message(), 'error' );
			return;
		}
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'rules_custom' );
		$rid   = 'custom_' . substr( md5( $name . $pattern . microtime() ), 0, 10 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$table,
			array(
				'rule_id'    => $rid,
				'name'       => $name ?: $rid,
				'enabled'    => 1,
				'rule_type'  => 'regex',
				'pattern'    => $pattern,
				'targets'    => wp_json_encode( array( 'all' ) ),
				'action'     => 'block',
				'severity'   => 'high',
				'cve'        => '',
				'sandbox_ok' => 1,
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			)
		);
		SquidSec_Shield_Rules_Engine::flush_cache();
		add_settings_error( 'sss', 'cr', 'Custom rule added: ' . $rid, 'updated' );
	}

	/**
	 * Notices.
	 */
	public static function notices() {
		settings_errors( 'sss' );
	}

	/**
	 * Sub-nav within Shield.
	 *
	 * @param string $current Current page slug.
	 */
	private static function subnav( $current ) {
		$primary = array(
			self::SLUG                 => 'Dashboard',
			'squidsec-shield-hardening' => 'Issues to fix',
			'squidsec-shield-logs'      => 'Activity',
			'squidsec-shield-settings'  => 'Settings',
		);
		$advanced = array(
			'squidsec-shield-waf'     => 'Firewall',
			'squidsec-shield-malware' => 'Scanners',
			'squidsec-shield-auth'    => 'Login security',
			'squidsec-shield-vuln'    => 'Plugin risks',
			'squidsec-shield-api'     => 'Developers',
		);
		echo '<nav class="sss-subnav" aria-label="Shield sections">';
		foreach ( $primary as $slug => $label ) {
			$url   = admin_url( 'admin.php?page=' . $slug );
			$class = ( $current === $slug ) ? ' class="current"' : '';
			echo '<a href="' . esc_url( $url ) . '"' . $class . '>' . esc_html( $label ) . '</a>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '<span class="sss-subnav-sep" title="Optional fine-tuning">Advanced</span>';
		foreach ( $advanced as $slug => $label ) {
			$url   = admin_url( 'admin.php?page=' . $slug );
			$class = ( $current === $slug ) ? ' class="current"' : '';
			echo '<a href="' . esc_url( $url ) . '"' . $class . '>' . esc_html( $label ) . '</a>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
		echo '</nav>';
	}

	/**
	 * Header — brand + version only (no threat jargon).
	 *
	 * @param string $title   Unused (kept for call-site compatibility).
	 * @param string $current Current slug for subnav.
	 * @param string $intro   Optional intro paragraph.
	 */
	private static function header( $title, $current, $intro = '' ) {
		$opts     = SquidSec_Shield_Options::all();
		$logo_url = SQUIDSEC_SHIELD_URL . 'assets/images/squidshield-logo.png';
		$logo_2x  = SQUIDSEC_SHIELD_URL . 'assets/images/squidshield-logo-2x.png';
		echo '<div class="wrap sss-wrap">';
		echo '<div class="sss-header">';
		echo '<div class="sss-header-brand">';
		echo '<img class="sss-header-logo" src="' . esc_url( $logo_url ) . '" srcset="' . esc_url( $logo_url ) . ' 1x, ' . esc_url( $logo_2x ) . ' 2x" width="42" height="51" alt="' . esc_attr( SQUIDSEC_SHIELD_NAME ) . '" />';
		echo '<div class="sss-header-main">';
		echo '<h1>' . esc_html( SQUIDSEC_SHIELD_NAME ) . '</h1>';
		echo '<p class="sss-header-sub">';
		echo '<span class="sss-header-ver">v' . esc_html( SQUIDSEC_SHIELD_VERSION ) . '</span>';
		if ( ! empty( $opts['pentest_mode'] ) ) {
			echo '<span class="sss-header-pill">' . esc_html__( 'Testing mode — logging only, not blocking', 'squidsec-shield' ) . '</span>';
		}
		echo '</p>';
		echo '</div></div></div>';
		self::subnav( $current );
		if ( $intro ) {
			echo '<p class="sss-page-intro">' . esc_html( $intro ) . '</p>';
		}
	}

	/** Footer. */
	private static function footer() {
		echo '</div>';
	}

	/** Nonce field. */
	private static function nonce() {
		wp_nonce_field( 'sss_admin' );
	}

	/**
	 * Dashboard — protection overview first.
	 */
	public static function page_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Dashboard',
			self::SLUG,
			'Install and activate — protection is automatic. This page shows what is running. Open Advanced only if you need to customize.'
		);

		$status  = SquidSec_Shield_Setup::overall_status();
		$layers  = SquidSec_Shield_Setup::protection_layers();
		$logs    = SquidSec_Shield_Audit_Log::query( array( 'limit' => 6 ) );
		$sens    = get_option( 'squidsec_shield_sensitive_cache', array() );
		$misc    = get_option( 'squidsec_shield_misconfig_cache', array() );
		$issue_n = count( $sens['files'] ?? array() );
		foreach ( $misc['findings'] ?? array() as $f ) {
			if ( ! empty( $f['remediable'] ) ) {
				$issue_n++;
			}
		}
		$opts       = SquidSec_Shield_Options::all();
		$layers_on  = 0;
		$layers_tot = count( $layers );
		foreach ( $layers as $layer ) {
			if ( ! empty( $layer['ok'] ) ) {
				$layers_on++;
			}
		}
		$pct = $layers_tot > 0 ? (int) round( ( $layers_on / $layers_tot ) * 100 ) : 0;
		?>
		<div class="sss-panel sss-panel-protect sss-dash-protect">
			<div class="sss-protect-head">
				<div>
					<h2><?php esc_html_e( 'Protection status', 'squidsec-shield' ); ?></h2>
					<p class="sss-help">
						<?php
						echo esc_html(
							$layers_on === $layers_tot
								? __( 'All automatic protections are on. You do not need to configure anything.', 'squidsec-shield' )
								: __( 'Some protections are off. Turn them back on below or re-apply recommended protection.', 'squidsec-shield' )
						);
						?>
					</p>
				</div>
				<div class="sss-protect-meter" role="img" aria-label="<?php echo esc_attr( sprintf( /* translators: 1: on, 2: total */ __( '%1$d of %2$d protections active', 'squidsec-shield' ), $layers_on, $layers_tot ) ); ?>">
					<div class="sss-protect-meter-ring" style="--sss-pct: <?php echo (int) $pct; ?>">
						<span class="sss-protect-meter-value"><?php echo (int) $pct; ?>%</span>
					</div>
					<span class="sss-protect-meter-caption">
						<?php
						printf(
							/* translators: 1: active count, 2: total */
							esc_html__( '%1$d / %2$d active', 'squidsec-shield' ),
							(int) $layers_on,
							(int) $layers_tot
						);
						?>
					</span>
				</div>
			</div>

			<div class="sss-protect-summary sss-summary-<?php echo esc_attr( $status['level'] ); ?>">
				<div class="sss-protect-summary-text">
					<strong><?php echo esc_html( $status['title'] ); ?></strong>
					<span><?php echo esc_html( $status['message'] ); ?></span>
				</div>
				<div class="sss-actions sss-protect-summary-actions">
					<?php if ( empty( $opts['enabled'] ) ) : ?>
						<form method="post"><?php self::nonce(); ?>
							<input type="hidden" name="sss_action" value="save_settings" />
							<input type="hidden" name="sss_bools[]" value="enabled" />
							<input type="hidden" name="sss[enabled]" value="1" />
							<button class="button button-primary"><?php esc_html_e( 'Turn protection on', 'squidsec-shield' ); ?></button>
						</form>
					<?php elseif ( ! empty( $opts['pentest_mode'] ) ) : ?>
						<form method="post"><?php self::nonce(); ?>
							<input type="hidden" name="sss_action" value="save_settings" />
							<input type="hidden" name="sss_bools[]" value="pentest_mode" />
							<button class="button button-primary"><?php esc_html_e( 'Resume full protection', 'squidsec-shield' ); ?></button>
						</form>
					<?php elseif ( $issue_n > 0 ) : ?>
						<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=squidsec-shield-hardening' ) ); ?>">
							<?php echo esc_html( sprintf( /* translators: %d: count */ __( 'Fix %d issue(s)', 'squidsec-shield' ), $issue_n ) ); ?>
						</a>
					<?php endif; ?>
					<form method="post"><?php self::nonce(); ?>
						<input type="hidden" name="sss_action" value="hardening" />
						<input type="hidden" name="profile" value="default" />
						<button class="button"><?php esc_html_e( 'Re-apply recommended protection', 'squidsec-shield' ); ?></button>
					</form>
					<form method="post"><?php self::nonce(); ?>
						<input type="hidden" name="sss_action" value="scan_misconfig" />
						<button class="button"><?php esc_html_e( 'Check site now', 'squidsec-shield' ); ?></button>
					</form>
				</div>
			</div>

			<div class="sss-protect-cards">
				<?php foreach ( $layers as $layer ) : ?>
					<?php $ok = ! empty( $layer['ok'] ); ?>
					<div class="sss-protect-card <?php echo $ok ? 'is-on' : 'is-off'; ?>">
						<div class="sss-protect-card-top">
							<span class="sss-status-pill <?php echo $ok ? 'sss-status-on' : 'sss-status-off'; ?>">
								<span class="sss-status-dot" aria-hidden="true"></span>
								<?php echo $ok ? esc_html__( 'Active', 'squidsec-shield' ) : esc_html__( 'Off', 'squidsec-shield' ); ?>
							</span>
						</div>
						<h3 class="sss-protect-card-title"><?php echo esc_html( $layer['label'] ); ?></h3>
						<p class="sss-protect-card-desc"><?php echo esc_html( $layer['detail'] ); ?></p>
					</div>
				<?php endforeach; ?>
			</div>

			<table class="sss-table sss-protect-table">
				<thead>
					<tr>
						<th class="sss-col-status" scope="col"><?php esc_html_e( 'Status', 'squidsec-shield' ); ?></th>
						<th class="sss-col-name" scope="col"><?php esc_html_e( 'Protection', 'squidsec-shield' ); ?></th>
						<th class="sss-col-desc" scope="col"><?php esc_html_e( 'What it does', 'squidsec-shield' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $layers as $layer ) : ?>
					<?php $ok = ! empty( $layer['ok'] ); ?>
					<tr class="<?php echo $ok ? 'sss-row-on' : 'sss-row-off'; ?>">
						<td class="sss-col-status">
							<span class="sss-status-pill <?php echo $ok ? 'sss-status-on' : 'sss-status-off'; ?>">
								<span class="sss-status-dot" aria-hidden="true"></span>
								<?php echo $ok ? esc_html__( 'Active', 'squidsec-shield' ) : esc_html__( 'Off', 'squidsec-shield' ); ?>
							</span>
						</td>
						<td class="sss-col-name"><span class="sss-protect-name"><?php echo esc_html( $layer['label'] ); ?></span></td>
						<td class="sss-col-desc"><span class="sss-protect-desc"><?php echo esc_html( $layer['detail'] ); ?></span></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<div class="sss-grid-2">
			<div class="sss-panel">
				<h2><?php esc_html_e( 'Latest activity', 'squidsec-shield' ); ?></h2>
				<p class="sss-help"><?php esc_html_e( 'Recent logins, blocked requests, and automatic scans — in plain language.', 'squidsec-shield' ); ?></p>
				<table class="sss-table">
					<thead><tr><th><?php esc_html_e( 'When', 'squidsec-shield' ); ?></th><th><?php esc_html_e( 'What happened', 'squidsec-shield' ); ?></th></tr></thead>
					<tbody>
					<?php foreach ( $logs as $row ) : ?>
						<tr>
							<td class="sss-muted"><?php echo esc_html( $row['created_at'] ); ?></td>
							<td><?php echo esc_html( self::human_event_label( $row['event_type'], $row['message'] ) ); ?></td>
						</tr>
					<?php endforeach; ?>
					<?php if ( ! $logs ) : ?>
						<tr><td colspan="2" class="sss-muted"><?php esc_html_e( 'No events yet — that is normal on a quiet site.', 'squidsec-shield' ); ?></td></tr>
					<?php endif; ?>
					</tbody>
				</table>
				<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=squidsec-shield-logs' ) ); ?>"><?php esc_html_e( 'See full activity →', 'squidsec-shield' ); ?></a></p>
			</div>
			<div class="sss-panel">
				<h2><?php esc_html_e( 'Optional extras', 'squidsec-shield' ); ?></h2>
				<ul class="sss-simple-list">
					<li>
						<strong><?php esc_html_e( 'Two-factor login (recommended for admins)', 'squidsec-shield' ); ?></strong>
						<span class="sss-help"><?php esc_html_e( 'Add an authenticator app code after your password. Set it up on your Profile — SquidShield already supports it.', 'squidsec-shield' ); ?></span>
						<p><a class="button" href="<?php echo esc_url( admin_url( 'profile.php' ) ); ?>"><?php esc_html_e( 'Set up on my profile', 'squidsec-shield' ); ?></a></p>
					</li>
					<li>
						<strong><?php esc_html_e( 'Email alerts', 'squidsec-shield' ); ?></strong>
						<span class="sss-help"><?php esc_html_e( 'Serious events can email the site admin automatically. Change the address under Settings if needed.', 'squidsec-shield' ); ?></span>
					</li>
				</ul>
			</div>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Plain-language event summary for the status feed.
	 *
	 * @param string $type    Event type.
	 * @param string $message Raw message.
	 * @return string
	 */
	private static function human_event_label( $type, $message ) {
		$map = array(
			'waf_match'            => 'Blocked a suspicious request',
			'login_failed'         => 'Failed login attempt',
			'login_success'        => 'Successful login',
			'login_lockout'        => 'Temporarily locked a guessing attack',
			'rate_limit'           => 'Slowing down repeated requests from one visitor',
			'malware_scan_start'   => 'Started a malware scan',
			'malware_scan_complete'=> 'Finished a malware scan',
			'fim_change'           => 'Important file change detected',
			'fim_baseline'         => 'Saved a snapshot of important files',
			'setup_secure_default' => 'Automatic protection enabled',
			'setup_auto_clean'     => 'Moved unsafe leftover files out of the web folder',
			'setup_first_scan'     => 'Ran first security check after install',
			'hardening_wizard'     => 'Applied recommended security settings',
			'user_enum_attempt'    => 'Blocked an attempt to list usernames',
			'remediation_delete'   => 'Removed a risky file',
			'remediation_quarantine' => 'Quarantined a risky file',
			'sensitive_scan'       => 'Found sensitive files that should not be public',
			'vuln_scan'            => 'Checked plugins for known issues',
			'misconfig_scan'       => 'Checked site configuration',
			'anomaly'              => 'Unusual traffic pattern noticed',
		);
		if ( isset( $map[ $type ] ) ) {
			return $map[ $type ];
		}
		return wp_html_excerpt( (string) $message, 100 );
	}

	/**
	 * WAF page.
	 */
	public static function page_waf() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Firewall',
			'squidsec-shield-waf',
			'Already on after install. This page is for fine-tuning. The firewall stops common hack attempts before they reach WordPress; leave the defaults unless you know you need a change.'
		);
		$rules   = SquidSec_Shield_Rules_Engine::get_rules();
		$patches = SquidSec_Shield_Virtual_Patch::list_patches();
		$opts    = SquidSec_Shield_Options::all();
		?>
		<div class="sss-panel">
			<h2>Firewall controls</h2>
			<form method="post"><?php self::nonce(); ?>
				<input type="hidden" name="sss_action" value="save_settings" />
				<?php
				self::bool_fields(
					array(
						'waf_enabled',
						'pentest_mode',
						'virtual_patch_enabled',
						'waf_block_sqli',
						'waf_block_xss',
						'waf_block_rce',
						'waf_block_lfi',
						'rate_limit_enabled',
						'bad_user_agents_enabled',
						'scraper_ua_enabled',
						'probe_patterns_enabled',
						'admin_ip_protection',
					)
				);
				self::toggle(
					'waf_enabled',
					'WAF enabled',
					'Master switch for the request firewall. When off, rules are not evaluated (login protection and other modules can still run).',
					$opts
				);
				self::toggle(
					'pentest_mode',
					'Pentest mode',
					'When ON, Shield still detects and logs attacks (audit log, dashboards, alerts) but does NOT block requests or lock out IPs. Use this while running a penetration test or tuning rules so legitimate testers are not locked out. Turn OFF for normal production protection.',
					$opts,
					'Leave OFF on live sites unless you are actively testing.'
				);
				self::toggle(
					'virtual_patch_enabled',
					'Virtual patching',
					'Applies CVE-oriented rules from the virtual-patches database. Rules that require a specific vulnerable plugin version stay idle if that software is not present — this reduces false positives.',
					$opts
				);
				self::toggle(
					'waf_block_sqli',
					'Block SQL injection (SQLi)',
					'Blocks request patterns that look like classic SQL injection (e.g. UNION SELECT, tautologies). May rarely affect unusual query strings that legitimately contain SQL-like text.',
					$opts
				);
				self::toggle(
					'waf_block_xss',
					'Block cross-site scripting (XSS)',
					'Blocks common XSS payloads such as script tags and javascript: URLs in request parameters.',
					$opts
				);
				self::toggle(
					'waf_block_rce',
					'Block remote code execution (RCE) patterns',
					'Blocks attempts to run system commands or eval-style payloads via the request (shell_exec, passthru, eval(base64…)).',
					$opts
				);
				self::toggle(
					'waf_block_lfi',
					'Block path traversal / LFI',
					'Blocks directory traversal (../) and probes for files like /etc/passwd or wp-config via the URL.',
					$opts
				);
				self::toggle(
					'rate_limit_enabled',
					'Rate limiting',
					'Limits how many requests an IP can make to sensitive WordPress endpoints (login, admin-ajax, REST, XML-RPC, and optionally wp-admin or general pages) in a short window. Excess traffic gets HTTP 429.',
					$opts
				);
				self::field(
					'ip_allowlist',
					'IP allowlist',
					'Comma-separated IPs or CIDRs that always bypass the WAF and rate limits (e.g. your office IP, monitoring probes). Example: 203.0.113.10, 198.51.100.0/24',
					implode( ', ', (array) $opts['ip_allowlist'] ),
					'text',
					array( 'class' => 'large-text', 'placeholder' => '203.0.113.10, 198.51.100.0/24' )
				);

				// New: dedicated admin IP allowlist (used for wp-admin/wp-login/admin-ajax protection)
				self::field(
					'admin_ip_allowlist',
					'Admin area IP allowlist',
					'Comma-separated IPs or CIDRs allowed to access /wp-admin, /wp-login.php and admin-ajax. Everyone else gets 403 on those paths. Leave empty to disable the extra IP gate (still protected by normal WAF + login protection).',
					implode( ', ', (array) $opts['admin_ip_allowlist'] ),
					'text',
					array( 'class' => 'large-text', 'placeholder' => '203.0.113.10, 198.51.100.0/24' )
				);

				// Block mode: soft (friendly page) or hard (plain 403)
				?>
				<p>
					<label for="sss_block_mode"><strong>Block response mode</strong></label><br />
					<select name="sss[block_mode]" id="sss_block_mode">
						<option value="soft" <?php selected( $opts['block_mode'] ?? 'soft', 'soft' ); ?>>Soft — friendly SquidShield block page (default)</option>
						<option value="hard" <?php selected( $opts['block_mode'] ?? 'soft', 'hard' ); ?>>Hard — plain 403 Forbidden (less information to scanners)</option>
					</select>
					<br /><span class="sss-help">Hard mode is useful when you want minimal HTML back to automated tools.</span>
				</p>
				<?php

				// Bad UA + probe patterns toggles + custom UA list
				self::toggle(
					'bad_user_agents_enabled',
					'Block obvious bad User-Agents',
					'Immediately block requests that come with curl, ffuf, wpscan, sqlmap, nuclei, gobuster and similar tool UAs. Major SEO/social bots are allowlisted separately and are never blocked here.',
					$opts
				);

				self::toggle(
					'scraper_ua_enabled',
					'Block stealth scraper User-Agents',
					'Block empty/bare Mozilla UAs, Mozlila typos, Firefox/78 Linux mass-crawlers, headless markers, and the custom list below. Matching IPs get a temporary block.',
					$opts
				);

				self::toggle(
					'probe_patterns_enabled',
					'Block common scanner probes',
					'Catch .env, wp-config, ../ traversal, /etc/passwd, .git, xmlrpc.php, base64_decode, etc. in the URL or query string even before the full rule engine.',
					$opts
				);

				self::field(
					'good_user_agents',
					'SEO / social allowlist (never blocked as bad/scraper UA)',
					'One entry per line, partial match. Defaults include Googlebot, Bingbot, Applebot, DuckDuckBot, Facebook/Meta crawlers. These still count as bots in analytics.',
					(string) $opts['good_user_agents'],
					'textarea',
					array( 'rows' => 5, 'class' => 'large-text code' )
				);

				self::field(
					'bad_user_agents',
					'Bad User-Agent list (one per line or partial match)',
					'One entry per line. Partial match against the User-Agent header (case-insensitive). Do not put Google/Bing/Facebook here; use the allowlist above.',
					(string) $opts['bad_user_agents'],
					'textarea',
					array( 'rows' => 6, 'class' => 'large-text code' )
				);

				self::field(
					'scraper_user_agents',
					'Extra scraper User-Agent fragments',
					'Additional partial matches for stealth scrapers (on top of built-in empty/bare/FF78/headless checks).',
					(string) $opts['scraper_user_agents'],
					'textarea',
					array( 'rows' => 3, 'class' => 'large-text code' )
				);
				// Per-area rate limit numbers (after the new admin/general ones were added in code)
				self::field(
					'rate_limit_ajax',
					'Admin-ajax rate limit',
					'Max requests per window for admin-ajax.',
					(int) $opts['rate_limit_ajax'],
					'number'
				);
				self::field(
					'rate_limit_rest',
					'REST API rate limit',
					'Max requests per window for REST endpoints.',
					(int) $opts['rate_limit_rest'],
					'number'
				);
				self::field(
					'rate_limit_login',
					'Login rate limit',
					'Max login attempts per window (very low recommended).',
					(int) $opts['rate_limit_login'],
					'number'
				);
				self::field(
					'rate_limit_xmlrpc',
					'XML-RPC rate limit',
					'Max requests per window for XML-RPC.',
					(int) $opts['rate_limit_xmlrpc'],
					'number'
				);
				self::field(
					'rate_limit_admin',
					'Admin area rate limit',
					'Requests per window for /wp-admin and related admin endpoints.',
					(int) $opts['rate_limit_admin'],
					'number'
				);
				self::field(
					'rate_limit_general',
					'General front-end rate limit (0 = off)',
					'Broad rate limit on normal pages (per IP per window). Default 90 slows full-site scrapers without hurting normal browsing. SEO allowlisted bots still hit this unless IP-allowlisted.',
					(int) $opts['rate_limit_general'],
					'number'
				);
				self::field(
					'rate_limit_window',
					'Rate limit window (seconds)',
					'Time window used for all rate limit counters above.',
					(int) $opts['rate_limit_window'],
					'number'
				);

				self::field(
					'ip_blocklist',
					'IP blocklist',
					'Comma-separated IPs or CIDRs that are always denied with HTTP 403, in addition to temporary blocks created after attacks.',
					implode( ', ', (array) $opts['ip_blocklist'] ),
					'text',
					array( 'class' => 'large-text' )
				);
				?>
				<p><button class="button button-primary">Save WAF settings</button></p>
			</form>
		</div>

		<div class="sss-panel">
			<h2>Virtual patches</h2>
			<p class="sss-help">Each row is a version-aware rule. <strong>Active</strong> means it can block matching attacks. <strong>Idle</strong> means the vulnerable component is not present, so the rule is skipped to avoid false positives. Official software updates remain the real fix; virtual patches buy time.</p>
			<table class="sss-table">
				<thead><tr><th>Rule</th><th>CVE</th><th>Status</th><th>Why</th><th>Official fix guidance</th></tr></thead>
				<tbody>
				<?php foreach ( $patches as $p ) : ?>
					<tr>
						<td><?php echo esc_html( $p['name'] ); ?><br /><code><?php echo esc_html( $p['id'] ); ?></code></td>
						<td><?php echo esc_html( $p['cve'] ?: '—' ); ?></td>
						<td><?php echo $p['enabled'] ? ( $p['applies'] ? '<span class="sss-ok">Active</span>' : '<span class="sss-muted">Idle</span>' ) : '<span class="sss-err">Disabled</span>'; ?></td>
						<td><?php echo esc_html( $p['reason'] ); ?></td>
						<td class="sss-muted"><?php echo esc_html( $p['fix_hint'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<div class="sss-panel">
			<h2>All rules (<?php echo count( $rules ); ?>)</h2>
			<p class="sss-help">Built-in WAF rules + virtual patches + any custom rules you added. Disable a rule if it false-positives on your site. Community rules live in <code>data/waf-rules.json</code> and <code>data/virtual-patches.json</code>.</p>
			<table class="sss-table">
				<thead><tr><th>ID</th><th>Name</th><th>Category</th><th>CVE</th><th>Enabled</th></tr></thead>
				<tbody>
				<?php foreach ( $rules as $r ) : ?>
					<tr>
						<td><code><?php echo esc_html( $r['id'] ); ?></code></td>
						<td><?php echo esc_html( $r['name'] ?? '' ); ?></td>
						<td><?php echo esc_html( $r['category'] ?? $r['type'] ?? '' ); ?></td>
						<td><?php echo esc_html( $r['cve'] ?? '' ); ?></td>
						<td>
							<form method="post" style="display:inline"><?php self::nonce(); ?>
								<input type="hidden" name="sss_action" value="toggle_rule" />
								<input type="hidden" name="rule_id" value="<?php echo esc_attr( $r['id'] ); ?>" />
								<input type="hidden" name="enabled" value="<?php echo empty( $r['enabled'] ) ? '1' : '0'; ?>" />
								<button class="button button-small"><?php echo empty( $r['enabled'] ) ? 'Enable' : 'Disable'; ?></button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<div class="sss-panel">
			<h2>Add a custom rule (sandboxed)</h2>
			<p class="sss-help">Advanced: add your own regex that runs against the request URI and body. Patterns are length-limited, checked for dangerous constructs, and must compile before they go live. Prefer narrow patterns to avoid blocking real users.</p>
			<form method="post"><?php self::nonce(); ?>
				<input type="hidden" name="sss_action" value="add_custom_rule" />
				<p><label>Name<br /><input type="text" name="rule_name" class="regular-text" placeholder="e.g. Block bad bot path" required /></label></p>
				<p><label>Regex pattern<br /><input type="text" name="rule_pattern" class="large-text" placeholder="e.g. (?i)/wp-content/uploads/.*\.php" required /></label></p>
				<button class="button">Add custom rule</button>
			</form>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Malware & FIM.
	 */
	public static function page_malware() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Scanners',
			'squidsec-shield-malware',
			'Already scheduled after install. Shield checks for malicious code and unexpected file changes automatically. Use this page only to run a scan now or review findings.'
		);
		$findings = SquidSec_Shield_Malware_Scanner::get_findings( 50 );
		?>
		<div class="sss-panel">
			<h2>Actions</h2>
			<p class="sss-help"><strong>Malware scan</strong> walks plugins, themes, mu-plugins, uploads, and odd root PHP files against the signature database, then spot-checks post content. <strong>FIM baseline</strong> snapshots hashes of core login/config files, active plugin mains, theme PHP, and mu-plugins. <strong>FIM check</strong> compares the live files to that baseline and looks for PHP dropped in uploads.</p>
			<div class="sss-actions">
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="scan_malware" /><button class="button button-primary">Start malware scan</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="fim_baseline" /><button class="button">Recreate FIM baseline</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="fim_check" /><button class="button">Run FIM check</button></form>
			</div>
		</div>
		<div class="sss-panel">
			<h2>Open findings</h2>
			<p class="sss-help">Review each hit carefully — some matches can be legitimate use of dangerous functions. <strong>Quarantine</strong> moves a file out of the web tree into <code>uploads/squidsec-shield-quarantine/</code> (does not permanently delete).</p>
			<table class="sss-table">
				<thead><tr><th>Severity</th><th>Title</th><th>Path</th><th>Line</th><th>Signature</th><th></th></tr></thead>
				<tbody>
				<?php foreach ( $findings as $f ) : ?>
					<tr>
						<td class="sss-sev <?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( $f['severity'] ); ?></td>
						<td><?php echo esc_html( $f['title'] ); ?><div class="sss-muted"><?php echo esc_html( wp_html_excerpt( (string) $f['detail'], 100 ) ); ?></div></td>
						<td><code><?php echo esc_html( $f['path'] ); ?></code></td>
						<td><?php echo (int) $f['line_no']; ?></td>
						<td><?php echo esc_html( $f['signature_id'] ); ?></td>
						<td class="sss-remediate-actions">
							<?php if ( $f['path'] && 0 !== strpos( $f['path'], 'post:' ) ) : ?>
							<form method="post" style="display:inline" onsubmit="return confirm('Quarantine this file?');"><?php self::nonce(); ?>
								<input type="hidden" name="sss_action" value="quarantine" />
								<input type="hidden" name="path" value="<?php echo esc_attr( $f['path'] ); ?>" />
								<button class="button button-small">Quarantine</button>
							</form>
							<form method="post" style="display:inline" onsubmit="return confirm('Permanently delete this file?');"><?php self::nonce(); ?>
								<input type="hidden" name="sss_action" value="delete_file" />
								<input type="hidden" name="path" value="<?php echo esc_attr( $f['path'] ); ?>" />
								<button class="button button-small button-link-delete">Delete</button>
							</form>
							<?php else : ?>
								<span class="sss-muted">Review content in admin</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				<?php if ( ! $findings ) : ?><tr><td colspan="6" class="sss-muted">No open findings. Run a scan if you have not yet.</td></tr><?php endif; ?>
				</tbody>
			</table>
			<p class="sss-muted">Signature DB version: <?php echo esc_html( (string) get_option( 'squidsec_shield_signature_version', 'n/a' ) ); ?> · Community file: <code>data/malware-signatures.json</code></p>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Auth page.
	 */
	public static function page_auth() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Login security',
			'squidsec-shield-auth',
			'Already protecting logins after install (guessing locks, generic errors, username hiding). Optional: add two-factor codes on your Profile, or CAPTCHA keys if you want an extra challenge box.'
		);
		$opts = SquidSec_Shield_Options::all();
		?>
		<div class="sss-panel">
			<h2>Login &amp; account protection</h2>
			<form method="post"><?php self::nonce(); ?>
				<input type="hidden" name="sss_action" value="save_settings" />
				<?php
				self::bool_fields(
					array(
						'login_protection',
						'hide_login_errors',
						'user_enum_prevention',
						'disable_author_archives',
						'disable_xmlrpc',
						'disable_xmlrpc_pingback',
						'totp_enabled',
						'captcha_on_login',
					)
				);
				self::toggle(
					'login_protection',
					'Login protection (brute force)',
					'Counts failed logins per IP (and username when enabled). After the max attempts, the IP is temporarily blocked and further tries are rejected. Successful login clears the counter.',
					$opts
				);
				self::field(
					'login_max_attempts',
					'Max failed attempts',
					'How many failures before lockout. Lower is stricter (more chance of locking out a forgetful admin). Recommended: 5.',
					(int) $opts['login_max_attempts'],
					'number',
					array( 'min' => 3, 'max' => 50, 'class' => 'small-text' )
				);
				self::field(
					'login_lockout_minutes',
					'Lockout duration (minutes)',
					'How long a blocked IP / username stays locked after exceeding max attempts.',
					(int) $opts['login_lockout_minutes'],
					'number',
					array( 'min' => 1, 'max' => 1440, 'class' => 'small-text' )
				);
				self::toggle(
					'hide_login_errors',
					'Generic login error messages',
					'Always show “Invalid credentials” instead of “unknown username” vs “wrong password”. That stops attackers from confirming which usernames exist.',
					$opts
				);
				self::toggle(
					'user_enum_prevention',
					'User enumeration prevention',
					'Stops anonymous visitors from listing users via the REST API, author archives, ?author=N redirects, oEmbed author fields, and user sitemaps. Logged-in editors still get what they need for the block editor.',
					$opts
				);
				self::toggle(
					'disable_author_archives',
					'Disable author archives',
					'Returns 404 for /author/username/ pages so usernames are harder to harvest from the public site.',
					$opts
				);
				self::toggle(
					'disable_xmlrpc',
					'Disable XML-RPC entirely',
					'Turns off xmlrpc.php. Good for most sites. Leave off (disabled) only if you still need Jetpack, the official mobile app via XML-RPC, or similar integrations.',
					$opts
				);
				self::toggle(
					'disable_xmlrpc_pingback',
					'Disable XML-RPC pingbacks only',
					'If full XML-RPC must stay on, at least remove pingback methods (common DDoS/amplification vector).',
					$opts
				);
				self::field(
					'custom_login_slug',
					'Custom login URL slug',
					'Optional. If set (e.g. secret-login), direct visits to /wp-login.php return 404 for GET requests; you log in via /secret-login/. Always bookmark the new URL. Leave empty to keep the default wp-login.php.',
					$opts['custom_login_slug'],
					'text',
					array( 'placeholder' => 'e.g. secret-login' )
				);
				?>
				<h2>Two-factor authentication (2FA)</h2>
				<?php
				self::toggle(
					'totp_enabled',
					'TOTP 2FA available',
					'Allows users to enable app-based codes (Google Authenticator, Authy, 1Password, etc.) on their Profile page. Pure TOTP — no SMS. Backup codes can be generated there too.',
					$opts
				);
				self::field(
					'totp_enforce_roles',
					'Enforce 2FA for roles',
					'Comma-separated WordPress roles that must enable 2FA (e.g. administrator, editor). Leave empty to keep 2FA optional for everyone. Users get a grace period before being pushed to set it up.',
					implode( ', ', (array) $opts['totp_enforce_roles'] ),
					'text',
					array( 'placeholder' => 'administrator' )
				);
				self::field(
					'totp_grace_days',
					'2FA grace period (days)',
					'How many days enforced roles may continue without 2FA after first reminder, before being redirected to their profile to finish setup.',
					(int) $opts['totp_grace_days'],
					'number',
					array( 'min' => 1, 'max' => 30, 'class' => 'small-text' )
				);
				?>
				<h2>CAPTCHA / Turnstile on login</h2>
				<p class="sss-help">Optional bot challenge on the login form. Use free Google reCAPTCHA v2 or Cloudflare Turnstile keys. Leave provider on “None” for local development or if you rely on rate limiting alone.</p>
				<div class="sss-field">
					<label class="sss-field-label" for="sss-captcha_provider">CAPTCHA provider</label>
					<select id="sss-captcha_provider" name="sss[captcha_provider]">
						<option value="none" <?php selected( $opts['captcha_provider'], 'none' ); ?>>None (no challenge widget)</option>
						<option value="recaptcha" <?php selected( $opts['captcha_provider'], 'recaptcha' ); ?>>Google reCAPTCHA v2</option>
						<option value="turnstile" <?php selected( $opts['captcha_provider'], 'turnstile' ); ?>>Cloudflare Turnstile</option>
					</select>
					<p class="sss-help">Choose the service that matches the keys you paste below.</p>
				</div>
				<?php
				self::toggle(
					'captcha_on_login',
					'Show CAPTCHA on login form',
					'When enabled and keys are set, login requires a successful CAPTCHA response in addition to username/password.',
					$opts
				);
				self::field( 'captcha_site_key', 'Site key (public)', 'Public key from reCAPTCHA or Turnstile dashboard — safe to embed in the page.', $opts['captcha_site_key'] );
				self::field( 'captcha_secret_key', 'Secret key', 'Private key used server-side to verify the CAPTCHA. Keep confidential.', $opts['captcha_secret_key'], 'password', array( 'autocomplete' => 'new-password' ) );
				?>
				<button class="button button-primary">Save auth settings</button>
			</form>
		</div>
		<div class="sss-panel">
			<h2>Where users set up 2FA</h2>
			<p>Each user enables TOTP, views backup codes, and can register optional WebAuthn/passkey credential IDs on their <a href="<?php echo esc_url( admin_url( 'profile.php' ) ); ?>">Profile</a> page under “SquidShield — Two-Factor Authentication”.</p>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Vuln page.
	 */
	public static function page_vuln() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Vulnerability Management & Plugin Risk',
			'squidsec-shield-vuln',
			'Compares installed core/plugins/themes against Shield’s local community vulnerability database and scores plugins for maintenance/supply-chain risk. This is advisory — always verify CVEs and update through official channels.'
		);
		$cache   = SquidSec_Shield_Vuln_Scanner::cached();
		$results = $cache['results'] ?? array();
		$risks   = SquidSec_Shield_Plugin_Risk::score_all();
		?>
		<div class="sss-panel">
			<p class="sss-help">Run a scan after plugin updates or weekly. Scores are 0–100 (higher = more risk). Virtual patches (WAF tab) may already mitigate some issues while you schedule updates.</p>
			<div class="sss-actions">
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="scan_vuln" /><button class="button button-primary">Run vulnerability scan</button></form>
			</div>
		</div>
		<div class="sss-panel">
			<h2>Vulnerability findings</h2>
			<table class="sss-table">
				<thead><tr><th>Score</th><th>Severity</th><th>Title</th><th>Component</th><th>Installed</th><th>CVE</th><th>Recommendation</th></tr></thead>
				<tbody>
				<?php foreach ( $results as $r ) : ?>
					<tr>
						<td><strong><?php echo (int) $r['score']; ?></strong></td>
						<td class="sss-sev <?php echo esc_attr( $r['severity'] ); ?>"><?php echo esc_html( $r['severity'] ); ?></td>
						<td><?php echo esc_html( $r['title'] ); ?><div class="sss-muted"><?php echo esc_html( wp_html_excerpt( (string) ( $r['description'] ?? '' ), 100 ) ); ?></div></td>
						<td><?php echo esc_html( ( $r['type'] ?? '' ) . ':' . ( $r['slug'] ?? '' ) ); ?></td>
						<td><?php echo esc_html( $r['installed'] ?? '' ); ?></td>
						<td><?php echo esc_html( $r['cve'] ?? '' ); ?></td>
						<td class="sss-muted"><?php echo esc_html( $r['recommendation'] ?? '' ); ?></td>
					</tr>
				<?php endforeach; ?>
				<?php if ( ! $results ) : ?><tr><td colspan="7" class="sss-muted">No results yet — run a scan. Empty can also mean nothing matched the local DB.</td></tr><?php endif; ?>
				</tbody>
			</table>
		</div>
		<div class="sss-panel">
			<h2>Plugin risk intelligence</h2>
			<p class="sss-help">Heuristic health score from update availability, missing metadata, inactive-but-installed plugins, and first-party SquidSec components. Not a CVE list — a prioritization aid.</p>
			<table class="sss-table">
				<thead><tr><th>Score</th><th>Plugin</th><th>Version</th><th>Active</th><th>Signals</th><th>Recommendation</th></tr></thead>
				<tbody>
				<?php foreach ( $risks as $r ) : ?>
					<tr>
						<td><strong><?php echo (int) $r['score']; ?></strong></td>
						<td><?php echo esc_html( $r['name'] ); ?></td>
						<td><?php echo esc_html( $r['version'] ); ?></td>
						<td><?php echo $r['active'] ? 'yes' : 'no'; ?></td>
						<td class="sss-muted"><?php echo esc_html( implode( '; ', $r['signals'] ) ); ?></td>
						<td class="sss-muted"><?php echo esc_html( $r['recommendation'] ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Hardening page.
	 */
	public static function page_hardening() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Issues to fix',
			'squidsec-shield-hardening',
			'Recommended cleanups only. Shield already applied safe defaults on install. Use the buttons below when something still needs a click — no command line required. Your live wp-config.php is never deleted.'
		);
		$misc  = get_option( 'squidsec_shield_misconfig_cache', array() );
		$sens  = get_option( 'squidsec_shield_sensitive_cache', array() );
		$rules = SquidSec_Shield_Sensitive_Files::suggested_server_rules();
		$sens_files = $sens['files'] ?? array();
		$misc_findings = $misc['findings'] ?? array();
		$sens_count = count( $sens_files );
		$fixable_misc = 0;
		foreach ( $misc_findings as $mf ) {
			if ( ! empty( $mf['remediable'] ) ) {
				$fixable_misc++;
			}
		}
		?>
		<div class="sss-panel">
			<h2>Hardening wizard</h2>
			<p class="sss-help"><strong>Default</strong> — balanced production baseline. <strong>Strict</strong> — tighter login limits and registration off. <strong>WooCommerce-aware</strong> — same security defaults but keeps registration available for customer accounts and raises AJAX rate limits for checkout.</p>
			<div class="sss-actions">
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="hardening" /><input type="hidden" name="profile" value="default" /><button class="button button-primary">Apply default hardening</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="hardening" /><input type="hidden" name="profile" value="strict" /><button class="button">Apply strict hardening</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="hardening" /><input type="hidden" name="profile" value="woocommerce" /><button class="button">WooCommerce-aware</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="scan_misconfig" /><button class="button">Rescan misconfigs &amp; sensitive files</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="protect_uploads" /><button class="button" title="Write .htaccess rules denying PHP execution in uploads">Protect uploads (.htaccess)</button></form>
				<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="cleanup_fingerprints" /><button class="button" title="Delete public readme/license files that leak versions">Remove readme/license files now</button></form>
			</div>
		</div>

		<?php if ( $sens_count || $fixable_misc ) : ?>
		<div class="sss-panel sss-remediate-bar">
			<h2>One-click remediation</h2>
			<p class="sss-help">Apply every safe automated fix: delete known-sensitive junk files (config backups, readme.html, dumps, debug.log, etc.) and fix remediable misconfigurations (uploads index, open registration, file editor, …). Live <code>wp-config.php</code> is never touched.</p>
			<div class="sss-actions">
				<form method="post" onsubmit="return confirm('Delete all remediable sensitive files and apply safe misconfig fixes? This cannot be undone (use Quarantine all if you want a recovery copy).');">
					<?php self::nonce(); ?>
					<input type="hidden" name="sss_action" value="fix_all_findings" />
					<button class="button button-primary">Fix all safe findings (<?php echo (int) ( $sens_count + $fixable_misc ); ?>)</button>
				</form>
				<form method="post" onsubmit="return confirm('Permanently delete all remediable sensitive files from the web root?');">
					<?php self::nonce(); ?>
					<input type="hidden" name="sss_action" value="remediate_all_sensitive" />
					<input type="hidden" name="mode" value="delete" />
					<button class="button">Delete all sensitive files (<?php echo (int) $sens_count; ?>)</button>
				</form>
				<form method="post" onsubmit="return confirm('Move all remediable sensitive files into uploads/squidsec-shield-quarantine/?');">
					<?php self::nonce(); ?>
					<input type="hidden" name="sss_action" value="remediate_all_sensitive" />
					<input type="hidden" name="mode" value="quarantine" />
					<button class="button">Quarantine all sensitive files</button>
				</form>
			</div>
		</div>
		<?php endif; ?>

		<div class="sss-panel">
			<h2>Sensitive files on disk</h2>
			<p class="sss-help">Config backups, <code>.env</code>, <code>debug.log</code>, and similar files should not sit in the web root. Use <strong>Delete</strong> to remove permanently, or <strong>Quarantine</strong> to move them to <code>uploads/squidsec-shield-quarantine/</code> (recoverable by an admin with filesystem access).</p>
			<?php if ( empty( $sens_files ) ) : ?>
				<p class="sss-muted">None detected. Run a rescan if you have not yet.</p>
			<?php else : ?>
			<table class="sss-table">
				<thead>
					<tr>
						<th>Risk</th>
						<th>Path</th>
						<th>Size</th>
						<th>Advice</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $sens_files as $f ) : ?>
					<tr>
						<td class="sss-sev <?php echo esc_attr( $f['risk'] ); ?>"><?php echo esc_html( $f['risk'] ); ?></td>
						<td><code><?php echo esc_html( $f['path'] ); ?></code></td>
						<td class="sss-muted"><?php echo ! empty( $f['size'] ) ? esc_html( size_format( (int) $f['size'] ) ) : '—'; ?></td>
						<td class="sss-muted"><?php echo esc_html( $f['advice'] ); ?></td>
						<td class="sss-remediate-actions">
							<?php if ( ! empty( $f['remediable'] ) ) : ?>
							<form method="post" style="display:inline" onsubmit="return confirm('Permanently delete <?php echo esc_js( $f['path'] ); ?>?');">
								<?php self::nonce(); ?>
								<input type="hidden" name="sss_action" value="delete_file" />
								<input type="hidden" name="sensitive" value="1" />
								<input type="hidden" name="path" value="<?php echo esc_attr( $f['path'] ); ?>" />
								<button class="button button-small button-link-delete">Delete</button>
							</form>
							<form method="post" style="display:inline" onsubmit="return confirm('Quarantine <?php echo esc_js( $f['path'] ); ?>?');">
								<?php self::nonce(); ?>
								<input type="hidden" name="sss_action" value="quarantine" />
								<input type="hidden" name="sensitive" value="1" />
								<input type="hidden" name="path" value="<?php echo esc_attr( $f['path'] ); ?>" />
								<button class="button button-small">Quarantine</button>
							</form>
							<?php else : ?>
								<span class="sss-muted">Manual only</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php endif; ?>
		</div>

		<div class="sss-panel">
			<h2>Misconfigurations</h2>
			<p class="sss-help">Interesting findings with guided or one-click fixes. Items marked manual need a human decision (e.g. renaming the admin user).</p>
			<?php if ( empty( $misc_findings ) ) : ?>
				<p class="sss-muted">No findings. Run a rescan to populate.</p>
			<?php else : ?>
			<table class="sss-table">
				<thead>
					<tr>
						<th>Severity</th>
						<th>Finding</th>
						<th>Recommendation</th>
						<th>Actions</th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $misc_findings as $f ) : ?>
					<tr>
						<td class="sss-sev <?php echo esc_attr( $f['severity'] ); ?>"><?php echo esc_html( $f['severity'] ); ?></td>
						<td>
							<strong><?php echo esc_html( $f['title'] ); ?></strong>
							<?php if ( ! empty( $f['path'] ) ) : ?>
								<br /><code><?php echo esc_html( $f['path'] ); ?></code>
							<?php endif; ?>
						</td>
						<td class="sss-muted"><?php echo esc_html( $f['fix'] ); ?></td>
						<td class="sss-remediate-actions">
							<?php if ( ! empty( $f['remediable'] ) ) : ?>
							<form method="post" style="display:inline" onsubmit="return confirm('Apply this fix?');">
								<?php self::nonce(); ?>
								<input type="hidden" name="sss_action" value="fix_misconfig" />
								<input type="hidden" name="finding_id" value="<?php echo esc_attr( $f['id'] ); ?>" />
								<input type="hidden" name="path" value="<?php echo esc_attr( $f['path'] ?? '' ); ?>" />
								<button class="button button-small button-primary">
									<?php
									$action = $f['action'] ?? '';
									if ( 'delete_file' === $action ) {
										echo 'Delete file';
									} elseif ( 'disable_registration' === $action ) {
										echo 'Disable registration';
									} elseif ( 'enable_file_editor_block' === $action ) {
										echo 'Disable file editor';
									} elseif ( 'create_uploads_index' === $action ) {
										echo 'Protect uploads';
									} else {
										echo 'Fix';
									}
									?>
								</button>
							</form>
							<?php else : ?>
								<span class="sss-muted">Manual</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php endif; ?>
		</div>

		<div class="sss-panel">
			<h2>Suggested server rules (defense in depth)</h2>
			<p class="sss-help">Even after deleting backups, keep server rules so future leaks are blocked. Copy into your Apache vhost/.htaccess or Nginx config. Shield can also write a focused uploads <code>.htaccess</code> via Protect uploads above (Apache only).</p>
			<h3>Apache</h3>
			<div class="sss-code" id="sss-apache"><?php echo esc_html( $rules['apache'] ); ?></div>
			<p><button type="button" class="button sss-copy" data-target="#sss-apache">Copy Apache rules</button></p>
			<h3>Nginx</h3>
			<div class="sss-code" id="sss-nginx"><?php echo esc_html( $rules['nginx'] ); ?></div>
			<p><button type="button" class="button sss-copy" data-target="#sss-nginx">Copy Nginx rules</button></p>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Logs page.
	 */
	public static function page_logs() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Audit Logs',
			'squidsec-shield-logs',
			'Searchable security event history: WAF matches (with rule/CVE), login success/failure, lockouts, scan results, FIM changes, plugin activations, and more. Export for incident response or compliance.'
		);
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$severity = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : '';
		$allowed_sev = array( 'critical', 'high', 'medium', 'low', 'info' );
		if ( ! in_array( $severity, $allowed_sev, true ) ) {
			$severity = '';
		}
		$logs = SquidSec_Shield_Audit_Log::query(
			array(
				'limit'    => 100,
				'search'   => $search,
				'severity' => $severity,
			)
		);
		?>
		<form method="get" class="sss-actions sss-log-filters">
			<input type="hidden" name="page" value="squidsec-shield-logs" />
			<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="Search message, URI, rule, CVE, IP…" class="regular-text" />
			<select name="severity">
				<option value=""><?php esc_html_e( 'All severities', 'squidsec-shield' ); ?></option>
				<?php foreach ( $allowed_sev as $sev ) : ?>
					<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( $severity, $sev ); ?>><?php echo esc_html( ucfirst( $sev ) ); ?></option>
				<?php endforeach; ?>
			</select>
			<button class="button">Filter</button>
			<?php if ( $search || $severity ) : ?>
				<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=squidsec-shield-logs' ) ); ?>"><?php esc_html_e( 'Clear', 'squidsec-shield' ); ?></a>
			<?php endif; ?>
		</form>
		<?php if ( $severity ) : ?>
			<p class="sss-help"><?php echo esc_html( sprintf( /* translators: %s: severity */ __( 'Showing %s events from the audit log. Threat level on the dashboard is derived from these 24-hour counts.', 'squidsec-shield' ), $severity ) ); ?></p>
		<?php endif; ?>
		<div class="sss-actions">
			<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="export_logs" /><input type="hidden" name="format" value="json" /><button class="button">Export JSON</button></form>
			<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="export_logs" /><input type="hidden" name="format" value="csv" /><button class="button">Export CSV</button></form>
			<form method="post"><?php self::nonce(); ?><input type="hidden" name="sss_action" value="block_ip" />
				<input type="text" name="ip" placeholder="Block IP permanently…" />
				<button class="button">Block IP</button>
			</form>
		</div>
		<p class="sss-help">Retention is controlled under Settings → Log retention. High/critical events can also email or webhook (Settings).</p>
		<div class="sss-panel">
			<table class="sss-table">
				<thead><tr><th>ID</th><th>Time (UTC)</th><th>Type</th><th>Sev</th><th>IP</th><th>User</th><th>Rule/CVE</th><th>Message</th></tr></thead>
				<tbody>
				<?php foreach ( $logs as $row ) : ?>
					<tr>
						<td><?php echo (int) $row['id']; ?></td>
						<td><?php echo esc_html( $row['created_at'] ); ?></td>
						<td><?php echo esc_html( $row['event_type'] ); ?></td>
						<td class="sss-sev <?php echo esc_attr( $row['severity'] ); ?>"><?php echo esc_html( $row['severity'] ); ?></td>
						<td><?php echo esc_html( $row['ip'] ); ?></td>
						<td><?php echo esc_html( $row['username'] ); ?></td>
						<td><?php echo esc_html( trim( $row['rule_id'] . ' ' . $row['cve'] ) ); ?></td>
						<td><?php echo esc_html( $row['message'] ); ?>
							<?php if ( ! empty( $row['uri'] ) ) : ?><div class="sss-muted"><?php echo esc_html( $row['method'] . ' ' . $row['uri'] ); ?></div><?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
		self::footer();
	}

	/**
	 * Settings page.
	 */
	public static function page_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'Settings',
			'squidsec-shield-settings',
			'Most sites never change these. Protection is already on after install. Only adjust if you are troubleshooting or a developer asks you to.'
		);
		$opts = SquidSec_Shield_Options::all();
		?>
		<div class="sss-panel">
			<h2><?php esc_html_e( 'Protection', 'squidsec-shield' ); ?></h2>
			<form method="post"><?php self::nonce(); ?>
				<input type="hidden" name="sss_action" value="save_settings" />
				<?php
				self::bool_fields( array( 'enabled', 'pentest_mode', 'remove_readme_license', 'daily_report', 'anomaly_detection', 'async_scans' ) );
				self::toggle(
					'enabled',
					'Protect this site',
					'Leave this on. Shield blocks attacks, hardens logins, and runs automatic checks. Turn off only if you are debugging a conflict.',
					$opts
				);
				self::toggle(
					'pentest_mode',
					'Testing mode (do not block)',
					'For security tests only: Shield still records attacks but lets them through. Turn this off when you finish testing so the site is protected again.',
					$opts,
					'Keep off for a normal live website.'
				);
				self::toggle(
					'remove_readme_license',
					'Delete readme & license files (hide versions)',
					'Removes public readme.html, readme.txt, license.txt, and similar files from WordPress core, plugins, and themes. These files are not needed to run the site and tell attackers exact versions. Runs on install and again after every plugin/theme/core update.',
					$opts
				);
				self::toggle(
					'daily_report',
					'Daily email summary',
					'Sends a once-per-day email with 24h event counts and the computed threat level. Uses the notify email below (or the WordPress admin email if empty).',
					$opts
				);
				self::toggle(
					'anomaly_detection',
					'Behavioral anomaly detection',
					'Watches for unusual spikes (e.g. admin-ajax or login traffic jumping vs the previous hour) and simple “impossible travel” signals when Cloudflare country headers are present. Results go to the audit log as high-severity anomalies.',
					$opts
				);
				self::toggle(
					'async_scans',
					'Async (background) malware scans',
					'When on, malware scans process file batches via WP-Cron so the admin page stays responsive. When off, scans run more synchronously (fine for CLI / small sites, heavier for large ones).',
					$opts
				);
				self::field(
					'notify_email',
					'Notify email',
					'Where high/critical alerts and daily reports go. Leave blank to use the site admin email (' . get_option( 'admin_email' ) . ').',
					$opts['notify_email'],
					'email',
					array( 'placeholder' => get_option( 'admin_email' ) )
				);
				self::field(
					'webhook_url',
					'Generic webhook URL',
					'Optional HTTPS endpoint (your SIEM, agent, or automation). Shield POSTs JSON for high/critical events: event, severity, message, context, site, timestamp.',
					$opts['webhook_url'],
					'url',
					array( 'class' => 'large-text', 'placeholder' => 'https://hooks.example.com/squidsec-shield' )
				);
				self::field(
					'slack_webhook',
					'Slack incoming webhook URL',
					'Optional Slack Incoming Webhook. Receives a short text alert for high/critical events. Create one in your Slack workspace apps settings.',
					$opts['slack_webhook'],
					'url',
					array( 'class' => 'large-text' )
				);
				self::field(
					'log_retention_days',
					'Log retention (days)',
					'Audit log rows older than this are deleted automatically on the daily maintenance run. Minimum 7.',
					(int) $opts['log_retention_days'],
					'number',
					array( 'min' => 7, 'max' => 365, 'class' => 'small-text' )
				);
				self::field(
					'scan_batch_size',
					'Malware scan batch size',
					'How many files to inspect per cron tick. Higher is faster but uses more CPU/memory per batch. Default 40 is a good balance.',
					(int) $opts['scan_batch_size'],
					'number',
					array( 'min' => 5, 'max' => 200, 'class' => 'small-text' )
				);
				?>
				<button class="button button-primary">Save settings</button>
			</form>
		</div>
		<div class="sss-panel">
			<h2>About</h2>
			<p class="sss-help"><?php echo esc_html( SQUIDSEC_SHIELD_NAME ); ?> v<?php echo esc_html( SQUIDSEC_SHIELD_VERSION ); ?> · Rule and signature databases ship under <code>data/</code> and can be extended with community or custom JSON packs.</p>
		</div>
		<?php
		self::footer();
	}

	/**
	 * API docs page.
	 */
	public static function page_api() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		self::header(
			'API & Automation',
			'squidsec-shield-api',
			'REST endpoints for agents, orchestration, and SIEM. Authenticate as an administrator (Application Password recommended for machines).'
		);
		$base = rest_url( 'squidsec-shield/v1' );
		?>
		<div class="sss-panel">
			<h2>REST API</h2>
			<p>Base URL: <code><?php echo esc_html( $base ); ?></code></p>
			<p class="sss-help">Example: <code>curl -u 'user:application_password' <?php echo esc_html( $base ); ?>/status</code></p>
			<table class="sss-table">
				<thead><tr><th>Method</th><th>Path</th><th>What it does</th></tr></thead>
				<tbody>
					<tr><td>GET</td><td><code>/status</code></td><td>Threat level, plugin version, 24h event counts, rule/signature versions</td></tr>
					<tr><td>GET</td><td><code>/logs</code></td><td>Query audit logs (<code>?search</code>, <code>?severity</code>, <code>?limit</code>)</td></tr>
					<tr><td>GET</td><td><code>/findings</code></td><td>Open malware findings</td></tr>
					<tr><td>GET</td><td><code>/rules</code></td><td>List WAF / virtual patch rules</td></tr>
					<tr><td>POST</td><td><code>/rules/{id}</code></td><td>Enable/disable a rule — body <code>{"enabled":true}</code></td></tr>
					<tr><td>GET/POST</td><td><code>/settings</code></td><td>Read or update Shield settings JSON</td></tr>
					<tr><td>POST</td><td><code>/scan/malware</code></td><td>Start a malware scan</td></tr>
					<tr><td>POST</td><td><code>/scan/vuln</code></td><td>Run vulnerability scan; returns findings</td></tr>
					<tr><td>POST</td><td><code>/scan/misconfig</code></td><td>Run misconfiguration scan</td></tr>
					<tr><td>GET</td><td><code>/virtual-patches</code></td><td>Virtual patch status (active vs idle)</td></tr>
					<tr><td>POST</td><td><code>/hardening</code></td><td>Apply wizard — body <code>{"profile":"default|strict|woocommerce"}</code></td></tr>
				</tbody>
			</table>
			<h2>Webhooks</h2>
			<p class="sss-help">Configure a webhook URL under Settings. High/critical events POST JSON similar to:</p>
			<div class="sss-code">{"event":"waf_match","severity":"high","message":"...","context":{},"site":"...","timestamp":"..."}</div>
			<h2>Extending anomaly rules</h2>
			<p class="sss-help">Developers can hook <code>squidsec_shield_anomaly_rules</code> to append custom anomaly findings without modifying the plugin core.</p>
		</div>
		<?php
		self::footer();
	}
}
