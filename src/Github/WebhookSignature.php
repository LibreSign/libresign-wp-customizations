<?php
/**
 * Signature of a GitHub webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * The HMAC GitHub sends in X-Hub-Signature-256.
 */
final class WebhookSignature {

	/**
	 * Whether the signature is the one the secret produces for the body.
	 *
	 * @param string $body      Raw request body.
	 * @param string $signature Signature header value.
	 * @param string $secret    Shared secret.
	 * @return bool
	 */
	public static function matches( $body, $signature, $secret ) {
		$body      = (string) $body;
		$secret    = trim( (string) $secret );
		$signature = trim( (string) $signature );

		if ( '' === $body || '' === $secret || '' === $signature ) {
			return false;
		}

		if ( 0 === stripos( $signature, 'sha256=' ) ) {
			$signature = substr( $signature, 7 );
		}

		if ( ! ctype_xdigit( $signature ) ) {
			return false;
		}

		return hash_equals( hash_hmac( 'sha256', $body, $secret ), strtolower( $signature ) );
	}
}
