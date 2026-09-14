<?php
/**
 * My Account endpoints served from the site root.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Account;

defined( 'ABSPATH' ) || exit;

/**
 * Recognizes a request for an account endpoint sitting at the site root.
 *
 * With My Account as the front page, /payment-methods/ and /lost-password/ are
 * valid screens and must not be collapsed back to / by a canonical redirect.
 */
final class RootEndpoint {

	/**
	 * Whether the path is the account page or one of its endpoints.
	 *
	 * @param string                $request_path Path of the request, with or without slashes around it.
	 * @param array<string, string> $query_vars   Endpoints registered by WooCommerce.
	 * @return bool
	 */
	public static function matches( $request_path, array $query_vars ) {
		$request_path = trim( (string) $request_path, '/' );

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
