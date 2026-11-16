<?php
/**
 * Test helper for the redirects that end the request.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Support;

use RuntimeException;

final class RedirectTrap {

	/**
	 * @var string|null
	 */
	private $location = null;

	/**
	 * @return string|null
	 */
	public function location_after( callable $request ) {
		add_filter( 'wp_redirect', array( $this, 'intercept' ) );

		try {
			$request();
		} catch ( RuntimeException $redirect ) {
			return $this->location;
		} finally {
			remove_filter( 'wp_redirect', array( $this, 'intercept' ) );
		}

		return $this->location;
	}

	/**
	 * @param string $location Where the browser would be sent.
	 * @throws RuntimeException Always.
	 */
	public function intercept( $location ): string {
		$this->location = $location;

		throw new RuntimeException( 'Redirected.' );
	}
}
