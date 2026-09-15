<?php
/**
 * Tests for the account endpoints served from the site root.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Account;

use LibreSign\WPCustomizations\Account\RootEndpoint;
use PHPUnit\Framework\TestCase;

/**
 * With My Account as the front page, these paths are screens and not the front page.
 */
final class RootEndpointTest extends TestCase {

	/**
	 * The endpoints WooCommerce registers on a store with Subscriptions.
	 *
	 * @return array<string, string>
	 */
	private static function query_vars() {
		return array(
			'order-pay'            => 'order-pay',
			'order-received'       => 'order-received',
			'orders'               => 'orders',
			'edit-account'         => 'edit-account',
			'edit-address'         => 'edit-address',
			'payment-methods'      => 'payment-methods',
			'lost-password'        => 'lost-password',
			'customer-logout'      => 'customer-logout',
			'subscriptions'        => 'subscriptions',
			'add-payment-method'   => '',
		);
	}

	/**
	 * @dataProvider provide_paths
	 *
	 * @param string $request_path Path of the request.
	 * @param bool   $expected     Whether it is an account endpoint.
	 */
	public function test_matches( $request_path, $expected ) {
		$this->assertSame( $expected, RootEndpoint::matches( $request_path, self::query_vars() ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: bool}>
	 */
	public static function provide_paths() {
		yield 'an endpoint at the root'          => array( '/payment-methods/', true );
		yield 'an endpoint with a value'         => array( '/edit-address/billing/', true );
		yield 'the my-account alias'             => array( '/my-account/', true );
		yield 'an endpoint under the alias'      => array( '/my-account/orders/', true );
		yield 'no slashes around the path'       => array( 'lost-password', true );
		yield 'the front page itself'            => array( '/', false );
		yield 'an empty path'                    => array( '', false );
		yield 'a page'                           => array( '/planos/', false );
		yield 'a post'                           => array( '/2026/09/hello-world/', false );
		yield 'an endpoint deeper in the path'   => array( '/planos/orders/', false );
		yield 'an endpoint that is not registered' => array( '/add-payment-method/', false );
	}

	public function test_a_store_without_endpoints_only_knows_the_alias() {
		$this->assertTrue( RootEndpoint::matches( '/my-account/', array() ) );
		$this->assertFalse( RootEndpoint::matches( '/orders/', array() ) );
	}
}
