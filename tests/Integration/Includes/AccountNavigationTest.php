<?php
/**
 * Characterization tests for the My Account navigation wiring.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Integration\Includes;

use WP_UnitTestCase;

/**
 * Covers the parts that read the request being rendered or hook into WooCommerce.
 *
 * WooCommerce is not loaded in the test suite, so what is asserted here is the
 * registration of the hooks and the behaviour of the callbacks when they are
 * called with the arguments WooCommerce passes them.
 */
final class AccountNavigationTest extends WP_UnitTestCase {

	public function tear_down() {
		global $wp;
		$wp->query_vars = array();

		parent::tear_down();
	}

	/**
	 * Pretend the request currently being rendered has these query vars.
	 *
	 * @param array<string, mixed> $query_vars Query vars.
	 * @return void
	 */
	private function render_request_with( $query_vars ) {
		global $wp;
		$wp->query_vars = $query_vars;
	}

	/**
	 * @dataProvider provide_hooks
	 *
	 * @param string $hook     Hook name.
	 * @param string $callback Callback name.
	 * @param int    $priority Expected priority.
	 */
	public function test_the_navigation_callbacks_are_hooked( $hook, $callback, $priority ) {
		$this->assertSame( $priority, has_filter( $hook, $callback ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string, 2: int}>
	 */
	public static function provide_hooks() {
		yield 'the navigation is filtered' => array(
			'woocommerce_account_menu_items',
			'libresign_filter_account_menu_items',
			20,
		);
		yield 'the entry classes are filtered' => array(
			'woocommerce_account_menu_item_classes',
			'libresign_filter_account_menu_item_classes',
			10,
		);
		yield 'the endpoint titles are registered on init' => array(
			'init',
			'libresign_register_account_endpoint_titles',
			10,
		);
		yield 'the payment methods heading is rendered' => array(
			'woocommerce_before_account_payment_methods',
			'libresign_render_payment_methods_section_title',
			5,
		);
		yield 'the addresses are rendered on the billing screen' => array(
			'woocommerce_account_payment-methods_endpoint',
			'libresign_render_addresses_on_payment_methods',
			20,
		);
		yield 'the addresses list is redirected' => array(
			'template_redirect',
			'libresign_redirect_addresses_to_billing',
			10,
		);
		yield 'the addresses description is replaced' => array(
			'woocommerce_my_account_my_address_description',
			'libresign_filter_my_address_description',
			10,
		);
	}

	public function test_the_endpoint_title_filters_are_registered_for_the_renamed_entries() {
		$this->assertSame( 20, has_filter( 'woocommerce_endpoint_subscriptions_title', 'libresign_filter_account_endpoint_title' ) );
		$this->assertSame( 20, has_filter( 'woocommerce_endpoint_orders_title', 'libresign_filter_account_endpoint_title' ) );
		$this->assertSame( 20, has_filter( 'woocommerce_endpoint_payment-methods_title', 'libresign_filter_account_endpoint_title' ) );
		$this->assertSame( 20, has_filter( 'woocommerce_endpoint_view-order_title', 'libresign_filter_view_order_endpoint_title' ) );
	}

	public function test_the_endpoint_title_follows_the_navigation_label() {
		$this->render_request_with( array( 'orders' => '' ) );

		$this->assertSame( 'Invoices', libresign_filter_account_endpoint_title( 'Orders', 'orders' ) );
	}

	public function test_the_endpoint_title_of_a_paginated_screen_carries_the_page_number() {
		$this->render_request_with( array( 'orders' => '3' ) );

		$this->assertSame( 'Invoices (page 3)', libresign_filter_account_endpoint_title( 'Orders', 'orders' ) );
	}

	public function test_the_first_page_is_not_numbered() {
		$this->render_request_with( array( 'orders' => '1' ) );

		$this->assertSame( 'Invoices', libresign_filter_account_endpoint_title( 'Orders', 'orders' ) );
	}

	public function test_an_entry_that_was_not_renamed_keeps_the_woocommerce_title() {
		$this->render_request_with( array( 'edit-account' => '' ) );

		$this->assertSame( 'Account details', libresign_filter_account_endpoint_title( 'Account details', 'edit-account' ) );
	}

	/**
	 * @dataProvider provide_detail_screens
	 *
	 * @param array<string, mixed> $query_vars Query vars of the request being rendered.
	 * @param string               $endpoint   Navigation entry being rendered.
	 * @param string[]             $classes    Classes WooCommerce computed.
	 * @param bool                 $active     Whether the entry ends up highlighted.
	 */
	public function test_a_detail_screen_highlights_the_entry_it_belongs_to( $query_vars, $endpoint, $classes, $active ) {
		$this->render_request_with( $query_vars );

		$filtered = libresign_filter_account_menu_item_classes( $classes, $endpoint );

		$this->assertSame( $active, in_array( 'is-active', $filtered, true ) );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>, 1: string, 2: string[], 3: bool}>
	 */
	public static function provide_detail_screens() {
		yield 'changing the payment method of a subscription' => array(
			array( 'subscription-payment-method' => '12' ),
			'subscriptions',
			array( 'subscriptions' ),
			true,
		);
		yield 'editing an address' => array(
			array( 'edit-address' => 'billing' ),
			'payment-methods',
			array( 'payment-methods' ),
			true,
		);
		yield 'an entry without detail screens' => array(
			array( 'edit-address' => 'billing' ),
			'orders',
			array( 'orders' ),
			false,
		);
		yield 'an entry whose detail screen is not being rendered' => array(
			array( 'orders' => '' ),
			'payment-methods',
			array( 'payment-methods' ),
			false,
		);
		yield 'an entry WooCommerce already highlighted' => array(
			array(),
			'orders',
			array( 'orders', 'is-active' ),
			true,
		);
	}

	public function test_the_classes_of_an_unrelated_entry_are_untouched() {
		$this->render_request_with( array( 'edit-address' => 'billing' ) );

		$this->assertSame( array( 'orders' ), libresign_filter_account_menu_item_classes( array( 'orders' ), 'orders' ) );
	}

	public function test_the_addresses_are_described_in_terms_of_the_subscription() {
		$description = apply_filters( 'woocommerce_my_account_my_address_description', 'These addresses will be used on the checkout page by default.' );

		$this->assertStringContainsString( 'invoices', $description );
		$this->assertStringNotContainsString( 'checkout', $description );
	}

	public function test_a_section_title_is_escaped() {
		ob_start();
		libresign_render_account_section_title( 'Payment <script>alert(1)</script> methods' );
		$html = ob_get_clean();

		$this->assertSame(
			'<h2 class="libresign-account-section-title">Payment &lt;script&gt;alert(1)&lt;/script&gt; methods</h2>',
			$html
		);
	}
}
