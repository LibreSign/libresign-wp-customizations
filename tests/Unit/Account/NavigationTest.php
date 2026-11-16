<?php
/**
 * Tests for the My Account navigation.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Account;

use LibreSign\WPCustomizations\Account\Navigation;
use PHPUnit\Framework\TestCase;

/**
 * Which entries the customer sees, how they are named and which one is active.
 */
final class NavigationTest extends TestCase {

	/**
	 * The navigation WooCommerce hands over on a store with Subscriptions.
	 *
	 * @return array<string, string>
	 */
	private static function woocommerce_menu() {
		return array(
			'dashboard'       => 'Dashboard',
			'orders'          => 'Orders',
			'subscriptions'   => 'Subscriptions',
			'downloads'       => 'Downloads',
			'edit-address'    => 'Addresses',
			'payment-methods' => 'Payment methods',
			'edit-account'    => 'Account details',
			'customer-logout' => 'Log out',
		);
	}

	public function test_keeps_five_entries_in_the_configured_order() {
		$this->assertSame(
			array( 'subscriptions', 'orders', 'payment-methods', 'edit-account', 'customer-logout' ),
			array_keys( Navigation::filter_items( self::woocommerce_menu() ) )
		);
	}

	public function test_renames_only_the_three_entries_whose_meaning_changed() {
		$menu = Navigation::filter_items( self::woocommerce_menu() );

		$this->assertSame( 'My subscription', $menu['subscriptions'] );
		$this->assertSame( 'Invoices', $menu['orders'] );
		$this->assertSame( 'Billing', $menu['payment-methods'] );
		$this->assertSame( 'Account details', $menu['edit-account'] );
		$this->assertSame( 'Log out', $menu['customer-logout'] );
	}

	/**
	 * @dataProvider provide_menus
	 *
	 * @param array<string, string> $items    Navigation handed over by WooCommerce.
	 * @param string[]              $expected Expected resulting keys.
	 */
	public function test_filter_items( $items, $expected ) {
		$this->assertSame( $expected, array_keys( Navigation::filter_items( $items ) ) );
	}

	/**
	 * @return iterable<string, array{0: array<string, string>, 1: string[]}>
	 */
	public static function provide_menus() {
		yield 'entries outside the list are dropped' => array(
			self::woocommerce_menu(),
			array( 'subscriptions', 'orders', 'payment-methods', 'edit-account', 'customer-logout' ),
		);
		yield 'unregistered endpoints are skipped' => array(
			array(
				'dashboard'       => 'Dashboard',
				'orders'          => 'Orders',
				'customer-logout' => 'Log out',
			),
			array( 'orders', 'customer-logout' ),
		);
		yield 'the input order is irrelevant' => array(
			array(
				'customer-logout' => 'Log out',
				'orders'          => 'Orders',
				'subscriptions'   => 'Subscriptions',
			),
			array( 'subscriptions', 'orders', 'customer-logout' ),
		);
		yield 'an empty navigation stays empty' => array( array(), array() );
		yield 'a navigation with nothing we keep' => array(
			array(
				'dashboard' => 'Dashboard',
				'downloads' => 'Downloads',
			),
			array(),
		);
	}

	public function test_renamed_entries_are_the_ones_with_a_matching_endpoint_title() {
		$this->assertSame(
			array( 'subscriptions', 'orders', 'payment-methods' ),
			array_keys( Navigation::labels() )
		);
	}

	public function test_detail_endpoints_are_mapped_to_the_entry_they_belong_to() {
		$aliases = Navigation::aliases();

		$this->assertSame( array( 'subscription-payment-method' ), $aliases['subscriptions'] );
		$this->assertSame( array( 'edit-address' ), $aliases['payment-methods'] );
		$this->assertSame( array( 'subscriptions', 'payment-methods' ), array_keys( $aliases ) );
	}

	/**
	 * @dataProvider provide_endpoint_titles
	 *
	 * @param string               $title      Title WooCommerce would use.
	 * @param string               $endpoint   Endpoint being rendered.
	 * @param array<string, mixed> $query_vars Query vars of the request being rendered.
	 * @param string               $expected   Expected title.
	 */
	public function test_endpoint_title( $title, $endpoint, $query_vars, $expected ) {
		$this->assertSame( $expected, Navigation::endpoint_title( $title, $endpoint, $query_vars ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string, 2: array<string, mixed>, 3: string}>
	 */
	public static function provide_endpoint_titles() {
		yield 'the title follows the navigation label' => array( 'Orders', 'orders', array( 'orders' => '' ), 'Invoices' );
		yield 'a paginated screen carries the page number' => array( 'Orders', 'orders', array( 'orders' => '3' ), 'Invoices (page 3)' );
		yield 'the first page is not numbered' => array( 'Orders', 'orders', array( 'orders' => '1' ), 'Invoices' );
		yield 'an entry that was not renamed keeps its title' => array( 'Account details', 'edit-account', array( 'edit-account' => '' ), 'Account details' );
		yield 'an endpoint absent from the request is not numbered' => array( 'Orders', 'orders', array(), 'Invoices' );
	}

	/**
	 * @dataProvider provide_detail_screens
	 *
	 * @param string[]             $classes    Classes WooCommerce computed.
	 * @param string               $endpoint   Navigation entry being rendered.
	 * @param array<string, mixed> $query_vars Query vars of the request being rendered.
	 * @param bool                 $active     Whether the entry ends up highlighted.
	 */
	public function test_filter_item_classes( $classes, $endpoint, $query_vars, $active ) {
		$filtered = Navigation::filter_item_classes( $classes, $endpoint, $query_vars );

		$this->assertSame( $active, in_array( 'is-active', $filtered, true ) );
	}

	/**
	 * @return iterable<string, array{0: string[], 1: string, 2: array<string, mixed>, 3: bool}>
	 */
	public static function provide_detail_screens() {
		yield 'changing the payment method of a subscription' => array(
			array( 'subscriptions' ),
			'subscriptions',
			array( 'subscription-payment-method' => '12' ),
			true,
		);
		yield 'editing an address' => array(
			array( 'payment-methods' ),
			'payment-methods',
			array( 'edit-address' => 'billing' ),
			true,
		);
		yield 'an entry without detail screens' => array(
			array( 'orders' ),
			'orders',
			array( 'edit-address' => 'billing' ),
			false,
		);
		yield 'an entry whose detail screen is not being rendered' => array(
			array( 'payment-methods' ),
			'payment-methods',
			array( 'orders' => '' ),
			false,
		);
		yield 'an entry WooCommerce already highlighted' => array(
			array( 'orders', 'is-active' ),
			'orders',
			array(),
			true,
		);
	}

	public function test_the_classes_of_an_unrelated_entry_are_untouched() {
		$this->assertSame(
			array( 'orders' ),
			Navigation::filter_item_classes( array( 'orders' ), 'orders', array( 'edit-address' => 'billing' ) )
		);
	}
}
