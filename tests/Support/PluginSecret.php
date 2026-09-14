<?php
/**
 * Test helper for the values the settings screen stores encrypted.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Support;

/**
 * Encrypts the way the sanitize callbacks of the settings screen do.
 */
final class PluginSecret {

	/**
	 * Encrypt a value with the key the plugin derives from the salts.
	 *
	 * @param string $value Plain text value.
	 * @return string
	 */
	public static function encrypt( $value ) {
		return base64_encode(
			openssl_encrypt(
				$value,
				'AES-256-CBC',
				hash( 'sha256', AUTH_KEY . SECURE_AUTH_SALT ),
				0,
				substr( hash( 'sha256', NONCE_SALT ), 0, 16 )
			)
		);
	}
}
