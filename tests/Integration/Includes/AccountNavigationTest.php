<?php
/**
 * Characterization tests for the My Account navigation wiring.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Integration\Includes;

use LibreSign\WPCustomizations\Tests\Support\RedirectTrap;
use WP_UnitTestCase;

/**
 * The hooks are registered, and the callbacks behave as expected when
 * WooCommerce calls them while rendering the account screens.
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
	 * @return int
	 */
	private function go_to_the_account_page() {
		$account_page_id = (int) self::factory()->post->create( array( 'post_type' => 'page' ) );
		update_option( 'woocommerce_myaccount_page_id', $account_page_id );
		$this->go_to( get_permalink( $account_page_id ) );

		return $account_page_id;
	}

	/**
	 * @param callable $render Callback that prints.
	 * @return string
	 */
	private function output_of( callable $render ) {
		ob_start();
		$render();

		return (string) ob_get_clean();
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

	public function test_an_invoice_is_titled_with_its_order_number() {
		$order = wc_create_order();
		$this->render_request_with( array( 'view-order' => (string) $order->get_id() ) );

		$this->assertSame( 'Invoice #' . $order->get_order_number(), libresign_filter_view_order_endpoint_title( 'Order' ) );
	}

	public function test_a_missing_invoice_keeps_the_title_woocommerce_gave_it() {
		$this->render_request_with( array( 'view-order' => '999999' ) );

		$this->assertSame( 'Order', libresign_filter_view_order_endpoint_title( 'Order' ) );
	}

	public function test_a_screen_other_than_an_invoice_keeps_its_title() {
		$this->render_request_with( array( 'orders' => '' ) );

		$this->assertSame( 'Order', libresign_filter_view_order_endpoint_title( 'Order' ) );
	}

	public function test_the_payment_methods_table_has_a_heading() {
		$this->assertSame(
			'<h2 class="libresign-account-section-title">Payment methods</h2>',
			$this->output_of( 'libresign_render_payment_methods_section_title' )
		);
	}

	public function test_the_addresses_are_rendered_on_the_billing_screen() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'customer' ) ) );

		$html = $this->output_of( 'libresign_render_addresses_on_payment_methods' );

		$this->assertStringStartsWith( '<h2 class="libresign-account-section-title">Addresses</h2>', $html );
		$this->assertStringContainsString( 'woocommerce-Addresses', $html );
		$this->assertStringContainsString( 'These addresses are used on your invoices and subscription charges.', $html );
	}

	public function test_the_addresses_list_is_sent_to_the_billing_screen() {
		$account_page_id = $this->go_to_the_account_page();
		$this->render_request_with( array( 'edit-address' => '' ) );

		$this->assertSame(
			add_query_arg( 'payment-methods', '', get_permalink( $account_page_id ) ),
			( new RedirectTrap() )->location_after( 'libresign_redirect_addresses_to_billing' )
		);
	}

	public function test_editing_one_address_stays_on_its_screen() {
		$this->go_to_the_account_page();
		$this->render_request_with( array( 'edit-address' => 'billing' ) );

		$this->assertNull( ( new RedirectTrap() )->location_after( 'libresign_redirect_addresses_to_billing' ) );
	}

	public function test_a_page_other_than_the_account_page_is_not_redirected() {
		$this->go_to( get_permalink( self::factory()->post->create( array( 'post_type' => 'page' ) ) ) );
		$this->render_request_with( array( 'edit-address' => '' ) );

		$this->assertNull( ( new RedirectTrap() )->location_after( 'libresign_redirect_addresses_to_billing' ) );
	}
}
