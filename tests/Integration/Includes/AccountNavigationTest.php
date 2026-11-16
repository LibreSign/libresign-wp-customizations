<?php
/**
 * Characterization tests for the My Account navigation wiring.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Integration\Includes;

use WP_UnitTestCase;

/**
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

	public function test_the_endpoint_title_is_built_from_the_request_being_rendered() {
		$this->render_request_with( array( 'orders' => '3' ) );

		$this->assertSame( 'Invoices (page 3)', libresign_filter_account_endpoint_title( 'Orders', 'orders' ) );
	}

	public function test_the_highlighted_entry_is_built_from_the_request_being_rendered() {
		$this->render_request_with( array( 'edit-address' => 'billing' ) );

		$this->assertContains(
			'is-active',
			libresign_filter_account_menu_item_classes( array( 'payment-methods' ), 'payment-methods' )
		);
	}

	public function test_the_navigation_is_reordered_when_woocommerce_filters_it() {
		$this->assertSame(
			array( 'orders', 'customer-logout' ),
			array_keys(
				libresign_filter_account_menu_items(
					array(
						'dashboard'       => 'Dashboard',
						'orders'          => 'Orders',
						'customer-logout' => 'Log out',
					)
				)
			)
		);
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
