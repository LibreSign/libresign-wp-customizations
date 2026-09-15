<?php
/**
 * Settings stored encrypted.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Settings;

defined( 'ABSPATH' ) || exit;

final class Secret {

	private const CIPHER = 'AES-256-CBC';

	private string $encryption_key;
	private string $initialization_vector;

	public function __construct( string $encryption_key, string $initialization_vector ) {
		$this->encryption_key        = $encryption_key;
		$this->initialization_vector = $initialization_vector;
	}

	public static function from_salts( string $auth_key, string $secure_auth_salt, string $nonce_salt ): self {
		return new self(
			hash( 'sha256', $auth_key . $secure_auth_salt ),
			substr( hash( 'sha256', $nonce_salt ), 0, 16 )
		);
	}

	public function encrypt( string $plain_value ): string {
		return base64_encode(
			(string) openssl_encrypt( $plain_value, self::CIPHER, $this->encryption_key, 0, $this->initialization_vector )
		);
	}

	/**
	 * Read a stored value, returning it untouched when it cannot be deciphered,
	 * so a value saved in plain text keeps working. Only for a value that stays
	 * on the site: decrypt_or_discard() is the one for a value that is sent.
	 */
	public function decrypt( string $stored_value ): string {
		$decoded_value = $this->decode( $stored_value );

		if ( false === $decoded_value ) {
			return trim( $stored_value );
		}

		return $this->decipher( $decoded_value ) ?? trim( $stored_value );
	}

	/**
	 * A value that is not base64 was never encrypted and is used as it is. A
	 * value that is base64 but does not decipher was encrypted with salts this
	 * installation no longer has: it is not the value and nobody outside may
	 * see it, so it is dropped instead of being sent.
	 */
	public function decrypt_or_discard( string $stored_value ): string {
		$decoded_value = $this->decode( $stored_value );

		if ( false === $decoded_value ) {
			return trim( $stored_value );
		}

		return (string) $this->decipher( $decoded_value );
	}

	/**
	 * @return string|false
	 */
	private function decode( string $stored_value ) {
		$stored_value = trim( $stored_value );

		return '' === $stored_value ? false : base64_decode( $stored_value, true );
	}

	private function decipher( string $decoded_value ): ?string {
		$decrypted_value = openssl_decrypt( $decoded_value, self::CIPHER, $this->encryption_key, 0, $this->initialization_vector );

		return false === $decrypted_value ? null : trim( $decrypted_value );
	}
}
