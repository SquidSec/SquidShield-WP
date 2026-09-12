<?php
/**
 * TOTP 2FA + backup codes + WebAuthn scaffolding.
 *
 * Pure PHP TOTP (RFC 6238) — no commercial dependencies.
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
 * Two-factor authentication.
 */
class SquidSec_Shield_Two_Factor {

	const META_SECRET   = 'squidsec_shield_totp_secret';
	const META_ENABLED  = 'squidsec_shield_totp_enabled';
	const META_BACKUP   = 'squidsec_shield_totp_backup';
	const META_GRACE    = 'squidsec_shield_totp_grace_until';
	const META_WEBAUTHN = 'squidsec_shield_webauthn_creds';

	/**
	 * Init.
	 */
	public static function init() {
		if ( ! SquidSec_Shield_Options::get( 'totp_enabled' ) ) {
			return;
		}
		add_action( 'login_form_validate_2fa', array( __CLASS__, 'login_form_2fa' ) );
		add_action( 'wp_login', array( __CLASS__, 'maybe_require_2fa' ), 5, 2 );
		add_action( 'show_user_profile', array( __CLASS__, 'profile_fields' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile_fields' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save_profile' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforce_roles' ) );
		add_action( 'login_form_webauthn', array( __CLASS__, 'login_form_webauthn' ) );
	}

	/**
	 * Generate base32 secret.
	 *
	 * @param int $length Length.
	 * @return string
	 */
	public static function generate_secret( $length = 16 ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret   = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= $alphabet[ random_int( 0, 31 ) ];
		}
		return $secret;
	}

	/**
	 * Base32 decode.
	 *
	 * @param string $b32 Base32.
	 * @return string
	 */
	public static function base32_decode( $b32 ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$b32      = strtoupper( preg_replace( '/[^A-Z2-7]/', '', $b32 ) );
		$buffer   = 0;
		$bits     = 0;
		$out      = '';
		for ( $i = 0, $len = strlen( $b32 ); $i < $len; $i++ ) {
			$val = strpos( $alphabet, $b32[ $i ] );
			if ( false === $val ) {
				continue;
			}
			$buffer = ( $buffer << 5 ) | $val;
			$bits  += 5;
			if ( $bits >= 8 ) {
				$bits  -= 8;
				$out   .= chr( ( $buffer >> $bits ) & 0xFF );
			}
		}
		return $out;
	}

	/**
	 * Compute TOTP code.
	 *
	 * @param string $secret Secret base32.
	 * @param int|null $time Time.
	 * @return string
	 */
	public static function totp( $secret, $time = null ) {
		if ( null === $time ) {
			$time = time();
		}
		$key    = self::base32_decode( $secret );
		$counter = pack( 'N*', 0, (int) floor( $time / 30 ) );
		$hash   = hash_hmac( 'sha1', $counter, $key, true );
		$offset = ord( substr( $hash, -1 ) ) & 0x0F;
		$code   = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % 1000000;
		return str_pad( (string) $code, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify TOTP or backup code.
	 *
	 * @param int    $user_id User.
	 * @param string $code    Code.
	 * @return bool
	 */
	public static function verify( $user_id, $code ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		// Backup codes.
		$backups = get_user_meta( $user_id, self::META_BACKUP, true );
		if ( is_array( $backups ) && isset( $backups[ $code ] ) ) {
			unset( $backups[ $code ] );
			update_user_meta( $user_id, self::META_BACKUP, $backups );
			return true;
		}
		$secret = get_user_meta( $user_id, self::META_SECRET, true );
		if ( ! $secret ) {
			return false;
		}
		// Window ±1 step.
		for ( $i = -1; $i <= 1; $i++ ) {
			if ( hash_equals( self::totp( $secret, time() + ( $i * 30 ) ), $code ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Generate backup codes.
	 *
	 * @return array map code => true
	 */
	public static function generate_backup_codes() {
		$codes = array();
		for ( $i = 0; $i < 8; $i++ ) {
			$c = strtolower( bin2hex( random_bytes( 4 ) ) );
			$codes[ $c ] = true;
		}
		return $codes;
	}

	/**
	 * After password auth — require 2FA if enabled.
	 *
	 * @param string  $user_login Login.
	 * @param WP_User $user      User.
	 */
	public static function maybe_require_2fa( $user_login, $user ) {
		if ( ! $user instanceof WP_User ) {
			return;
		}
		// Skip when already completing 2FA for this request.
		if ( ! empty( $GLOBALS['squidsec_shield_2fa_passed'] ) ) {
			return;
		}
		if ( ! get_user_meta( $user->ID, self::META_ENABLED, true ) ) {
			return;
		}
		// Mark session pending 2FA.
		wp_clear_auth_cookie();
		$token = wp_generate_password( 32, false );
		set_transient( 'sss_2fa_' . $token, $user->ID, 10 * MINUTE_IN_SECONDS );
		$redirect = add_query_arg(
			array(
				'action'    => 'validate_2fa',
				'sss_token' => $token,
			),
			wp_login_url()
		);
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * 2FA login form handler.
	 */
	public static function login_form_2fa() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token = isset( $_REQUEST['sss_token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['sss_token'] ) ) : '';
		$user_id = $token ? (int) get_transient( 'sss_2fa_' . $token ) : 0;
		if ( ! $user_id ) {
			wp_die( esc_html__( '2FA session expired. Please log in again.', 'squidsec-shield' ) );
		}

		$error = '';
		if ( 'POST' === SquidSec_Shield_Helpers::request_method() ) {
			check_admin_referer( 'sss_2fa' );
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$code = isset( $_POST['sss_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['sss_2fa_code'] ) ) : '';
			if ( self::verify( $user_id, $code ) ) {
				delete_transient( 'sss_2fa_' . $token );
				$GLOBALS['squidsec_shield_2fa_passed'] = true;
				wp_set_auth_cookie( $user_id, true );
				$user = get_user_by( 'id', $user_id );
				if ( $user ) {
					do_action( 'wp_login', $user->user_login, $user );
				}
				wp_safe_redirect( admin_url() );
				exit;
			}
			$error = __( 'Invalid authentication code.', 'squidsec-shield' );
			SquidSec_Shield_Audit_Log::write( '2fa_failed', 'medium', 'Invalid 2FA for user ' . $user_id );
		}

		login_header( __( 'Two-Factor Authentication', 'squidsec-shield' ) );
		if ( $error ) {
			echo '<div id="login_error">' . esc_html( $error ) . '</div>';
		}
		echo '<form method="post" action="' . esc_url( add_query_arg( array( 'action' => 'validate_2fa', 'sss_token' => $token ), wp_login_url() ) ) . '">';
		wp_nonce_field( 'sss_2fa' );
		echo '<p><label for="sss_2fa_code">' . esc_html__( 'Authentication code', 'squidsec-shield' ) . '</label><br />';
		echo '<input type="text" name="sss_2fa_code" id="sss_2fa_code" class="input" size="20" autocomplete="one-time-code" autofocus /></p>';
		echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__( 'Verify', 'squidsec-shield' ) . '" /></p>';
		echo '<p class="description">' . esc_html__( 'Enter the 6-digit code from your authenticator app, or a backup code.', 'squidsec-shield' ) . '</p>';
		echo '</form>';
		login_footer();
		exit;
	}

	/**
	 * WebAuthn login placeholder (challenge flow documented for future credential use).
	 */
	public static function login_form_webauthn() {
		login_header( 'WebAuthn' );
		echo '<p>' . esc_html__( 'WebAuthn/passkey credentials can be registered in your profile. Use TOTP as primary second factor.', 'squidsec-shield' ) . '</p>';
		login_footer();
		exit;
	}

	/**
	 * Profile UI.
	 *
	 * @param WP_User $user User.
	 */
	public static function profile_fields( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$enabled = (bool) get_user_meta( $user->ID, self::META_ENABLED, true );
		$secret  = get_user_meta( $user->ID, self::META_SECRET, true );
		if ( ! $secret ) {
			$pending = get_transient( 'sss_totp_pending_' . $user->ID );
			if ( ! is_string( $pending ) || $pending === '' ) {
				$pending = self::generate_secret();
				set_transient( 'sss_totp_pending_' . $user->ID, $pending, DAY_IN_SECONDS );
			}
			$secret = $pending;
		}
		$issuer = rawurlencode( wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
		$label  = rawurlencode( $user->user_email );
		$otpauth = "otpauth://totp/{$issuer}:{$label}?secret={$secret}&issuer={$issuer}&digits=6&period=30";
		$creds  = get_user_meta( $user->ID, self::META_WEBAUTHN, true );
		if ( ! is_array( $creds ) ) {
			$creds = array();
		}
		?>
		<h2><?php esc_html_e( 'SquidShield — Two-Factor Authentication', 'squidsec-shield' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'TOTP (Authenticator app)', 'squidsec-shield' ); ?></th>
				<td>
					<label><input type="checkbox" name="sss_totp_enabled" value="1" <?php checked( $enabled ); ?> /> <?php esc_html_e( 'Enable TOTP 2FA', 'squidsec-shield' ); ?></label>
					<p class="description"><?php esc_html_e( 'Scan this secret in Google Authenticator, Authy, or any TOTP app:', 'squidsec-shield' ); ?></p>
					<code style="user-select:all"><?php echo esc_html( $secret ); ?></code>
					<p class="description"><a href="<?php echo esc_url( $otpauth ); ?>"><?php esc_html_e( 'otpauth link', 'squidsec-shield' ); ?></a></p>
					<p>
						<label><?php esc_html_e( 'Confirm code to enable/save', 'squidsec-shield' ); ?><br />
						<input type="text" name="sss_totp_confirm" class="regular-text" autocomplete="one-time-code" /></label>
					</p>
					<p>
						<label><input type="checkbox" name="sss_totp_regen_backup" value="1" /> <?php esc_html_e( 'Regenerate backup codes on save', 'squidsec-shield' ); ?></label>
					</p>
				</td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'WebAuthn / Passkeys', 'squidsec-shield' ); ?></th>
				<td>
					<p class="description"><?php esc_html_e( 'Registered credentials (hardware keys / passkeys):', 'squidsec-shield' ); ?> <?php echo esc_html( (string) count( $creds ) ); ?></p>
					<p class="description"><?php esc_html_e( 'Register a new credential name and public key material (advanced). Prefer platform passkey enrollment via supported browsers.', 'squidsec-shield' ); ?></p>
					<input type="text" name="sss_webauthn_name" class="regular-text" placeholder="<?php esc_attr_e( 'Credential name (e.g. YubiKey)', 'squidsec-shield' ); ?>" />
					<input type="text" name="sss_webauthn_id" class="regular-text" placeholder="<?php esc_attr_e( 'Credential ID (base64)', 'squidsec-shield' ); ?>" />
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Save profile 2FA.
	 *
	 * @param int $user_id User ID.
	 */
	public static function save_profile( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$want = ! empty( $_POST['sss_totp_enabled'] );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$code = isset( $_POST['sss_totp_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['sss_totp_confirm'] ) ) : '';
		$secret = get_user_meta( $user_id, self::META_SECRET, true );
		if ( ! $secret ) {
			$pending = get_transient( 'sss_totp_pending_' . $user_id );
			if ( is_string( $pending ) && $pending !== '' ) {
				$secret = $pending;
			}
		}

		if ( $want ) {
			if ( $code && $secret && hash_equals( self::totp( $secret ), preg_replace( '/\s+/', '', $code ) ) ) {
				update_user_meta( $user_id, self::META_SECRET, $secret );
				update_user_meta( $user_id, self::META_ENABLED, 1 );
				delete_transient( 'sss_totp_pending_' . $user_id );
			} elseif ( ! get_user_meta( $user_id, self::META_ENABLED, true ) ) {
				add_settings_error( 'sss_2fa', 'sss_2fa', __( 'Invalid TOTP code — 2FA not enabled.', 'squidsec-shield' ), 'error' );
			}
		} else {
			delete_user_meta( $user_id, self::META_ENABLED );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['sss_totp_regen_backup'] ) ) {
			$codes = self::generate_backup_codes();
			update_user_meta( $user_id, self::META_BACKUP, $codes );
			set_transient( 'sss_backup_flash_' . $user_id, array_keys( $codes ), 60 );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$wname = isset( $_POST['sss_webauthn_name'] ) ? sanitize_text_field( wp_unslash( $_POST['sss_webauthn_name'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$wid = isset( $_POST['sss_webauthn_id'] ) ? sanitize_text_field( wp_unslash( $_POST['sss_webauthn_id'] ) ) : '';
		if ( $wname && $wid ) {
			$creds = get_user_meta( $user_id, self::META_WEBAUTHN, true );
			if ( ! is_array( $creds ) ) {
				$creds = array();
			}
			$creds[] = array(
				'name'       => $wname,
				'id'         => $wid,
				'created_at' => gmdate( 'c' ),
			);
			update_user_meta( $user_id, self::META_WEBAUTHN, $creds );
		}
	}

	/**
	 * Enforce 2FA for selected roles with grace period.
	 */
	public static function enforce_roles() {
		if ( ! is_user_logged_in() || wp_doing_ajax() ) {
			return;
		}
		$roles = SquidSec_Shield_Options::get( 'totp_enforce_roles', array() );
		if ( ! is_array( $roles ) || empty( $roles ) ) {
			return;
		}
		$user = wp_get_current_user();
		$need = false;
		foreach ( (array) $user->roles as $r ) {
			if ( in_array( $r, $roles, true ) ) {
				$need = true;
				break;
			}
		}
		if ( ! $need || get_user_meta( $user->ID, self::META_ENABLED, true ) ) {
			return;
		}
		$grace = get_user_meta( $user->ID, self::META_GRACE, true );
		if ( ! $grace ) {
			$days  = max( 1, (int) SquidSec_Shield_Options::get( 'totp_grace_days', 7 ) );
			$grace = time() + ( $days * DAY_IN_SECONDS );
			update_user_meta( $user->ID, self::META_GRACE, $grace );
		}
		if ( time() > (int) $grace ) {
			// Force profile setup.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
			if ( false === strpos( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), 'profile.php' ) ) {
				wp_safe_redirect( admin_url( 'profile.php#sss-2fa' ) );
				exit;
			}
		} else {
			add_action( 'admin_notices', static function () use ( $grace ) {
				echo '<div class="notice notice-warning"><p>';
				echo esc_html( sprintf(
					/* translators: %s: date */
					__( 'SquidShield: Please enable two-factor authentication before %s.', 'squidsec-shield' ),
					gmdate( 'Y-m-d', (int) $grace )
				) );
				echo ' <a href="' . esc_url( admin_url( 'profile.php' ) ) . '">' . esc_html__( 'Set up now', 'squidsec-shield' ) . '</a></p></div>';
			} );
		}
	}
}
