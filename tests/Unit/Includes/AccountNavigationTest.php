<?php
/**
 * Characterization tests for the My Account navigation decisions.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Includes;

use PHPUnit\Framework\TestCase;

/**
 * libresign_filter_account_menu_items() only maps an array to another array.
 */
final class AccountNavigationTest extends TestCase {

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
			array_keys( libresign_filter_account_menu_items( self::woocommerce_menu() ) )
		);
	}

	public function test_renames_only_the_three_entries_whose_meaning_changed() {
		$menu = libresign_filter_account_menu_items( self::woocommerce_menu() );

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
	public function test_filter_account_menu_items( $items, $expected ) {
		$this->assertSame( $expected, array_keys( libresign_filter_account_menu_items( $items ) ) );
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
			array_keys( libresign_get_account_menu_labels() ),
			array( 'subscriptions', 'orders', 'payment-methods' )
		);
	}

	public function test_detail_endpoints_are_mapped_to_the_entry_they_belong_to() {
		$aliases = libresign_get_account_menu_item_aliases();

		$this->assertSame( array( 'subscription-payment-method' ), $aliases['subscriptions'] );
		$this->assertSame( array( 'edit-address' ), $aliases['payment-methods'] );
		$this->assertSame( array( 'subscriptions', 'payment-methods' ), array_keys( $aliases ) );
	}
}
