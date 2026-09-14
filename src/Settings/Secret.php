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
	private $key;

	/**
	 * Initialization vector.
	 *
	 * @var string
	 */
	private $iv;

	/**
	 * @param string $key Encryption key.
	 * @param string $iv  Initialization vector.
	 */
	public function __construct( $key, $iv ) {
		$this->key = (string) $key;
		$this->iv  = (string) $iv;
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
	 * Encrypt a value for storage, leaving an already encrypted one untouched.
	 *
	 * WordPress runs the sanitize callback of an option again when
	 * update_option() hands a value that does not exist yet to add_option(), so
	 * encrypting has to be idempotent or the value is stored encrypted twice.
	 *
	 * @param string $value Plain text value.
	 * @return string
	 */
	public function encrypt( $value ) {
		$value = trim( (string) $value );

		if ( $this->decrypt( $value ) !== $value ) {
			return $value;
		}

		return base64_encode( (string) openssl_encrypt( $value, self::CIPHER, $this->key, 0, $this->iv ) );
	}

	/**
	 * Read a stored value, returning it untouched when it is not encrypted.
	 *
	 * A value saved before the encryption existed, or by hand, is stored in
	 * plain text and has to keep working.
	 *
	 * @param string $value Stored value.
	 * @return string
	 */
	public function decrypt( $value ) {
		$value = trim( (string) $value );

		if ( '' === $value ) {
			return '';
		}

		$decoded = base64_decode( $value, true );

		if ( false === $decoded ) {
			return $value;
		}

		$decrypted = openssl_decrypt( $decoded, self::CIPHER, $this->key, 0, $this->iv );

		return false === $decrypted ? $value : trim( $decrypted );
	}
}
