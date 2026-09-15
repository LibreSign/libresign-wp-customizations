<?php
/**
 * My Account endpoints served from the site root.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Account;

defined( 'ABSPATH' ) || exit;

/**
 * With My Account as the front page, /payment-methods/ and /lost-password/ are
 * screens and must not be collapsed back to / by a canonical redirect.
 */
final class RootEndpoint {

	/**
	 * @param array<string, string> $query_vars Endpoints registered by WooCommerce.
	 */
	public static function matches( string $request_path, array $query_vars ): bool {
		$request_path = trim( $request_path, '/' );

		if ( '' === $request_path ) {
			return false;
		}

		$segments   = explode( '/', $request_path );
		$first_slug = reset( $segments );

		if ( 'my-account' === $first_slug ) {
			return true;
		}

		foreach ( $query_vars as $query_var ) {
			if ( ! empty( $query_var ) && $query_var === $first_slug ) {
				return true;
			}
		}

		return false;
	}
}
