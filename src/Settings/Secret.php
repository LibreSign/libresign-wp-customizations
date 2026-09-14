<?php
/**
 * Settings stored encrypted.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Encrypts and decrypts the deploy token and the webhook secret.
 *
 * The key is derived from the salts of the installation, so a database copied
 * to another installation carries values that cannot be read there.
 */
final class Secret {

	private const CIPHER = 'AES-256-CBC';

	/**
	 * Encryption key.
	 *
	 * @var string
	 */
	private $encryption_key;

	/**
	 * Initialization vector.
	 *
	 * @var string
	 */
	private $initialization_vector;

	/**
	 * @param string $encryption_key        Encryption key.
	 * @param string $initialization_vector Initialization vector.
	 */
	public function __construct( $encryption_key, $initialization_vector ) {
		$this->encryption_key        = (string) $encryption_key;
		$this->initialization_vector = (string) $initialization_vector;
	}

	/**
	 * Derive the key from the salts of the installation.
	 *
	 * @param string $auth_key         AUTH_KEY.
	 * @param string $secure_auth_salt SECURE_AUTH_SALT.
	 * @param string $nonce_salt       NONCE_SALT.
	 * @return self
	 */
	public static function from_salts( $auth_key, $secure_auth_salt, $nonce_salt ) {
		return new self(
			hash( 'sha256', $auth_key . $secure_auth_salt ),
			substr( hash( 'sha256', $nonce_salt ), 0, 16 )
		);
	}

	/**
	 * Encrypt a value for storage.
	 *
	 * @param string $plain_value Plain text value.
	 * @return string
	 */
	public function encrypt( $plain_value ) {
		return base64_encode(
			(string) openssl_encrypt( (string) $plain_value, self::CIPHER, $this->encryption_key, 0, $this->initialization_vector )
		);
	}

	/**
	 * Read a stored value, returning it untouched when it is not encrypted.
	 *
	 * A value saved before the encryption existed, or by hand, is stored in
	 * plain text and has to keep working.
	 *
	 * @param string $stored_value Stored value.
	 * @return string
	 */
	public function decrypt( $stored_value ) {
		$stored_value = trim( (string) $stored_value );

		if ( '' === $stored_value ) {
			return '';
		}

		$decoded_value = base64_decode( $stored_value, true );

		if ( false === $decoded_value ) {
			return $stored_value;
		}

		$decrypted_value = openssl_decrypt( $decoded_value, self::CIPHER, $this->encryption_key, 0, $this->initialization_vector );

		return false === $decrypted_value ? $stored_value : trim( $decrypted_value );
	}
}
