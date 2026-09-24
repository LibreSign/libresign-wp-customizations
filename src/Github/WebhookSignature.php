<?php
/**
 * Signature of a GitHub webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

final class WebhookSignature {

	public static function matches( string $body, string $signature, string $secret ): bool {
		$secret    = trim( $secret );
		$signature = trim( $signature );

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
