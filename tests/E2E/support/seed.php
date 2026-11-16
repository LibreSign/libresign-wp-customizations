<?php

defined( 'ABSPATH' ) || exit;

$customer_password = isset( $args[0] ) ? (string) $args[0] : '';

if ( '' === $customer_password ) {
	WP_CLI::error( 'Usage: wp eval-file seed.php <customer-password>' );
}

if ( ! function_exists( 'wcs_create_subscription' ) ) {
	WP_CLI::error( 'WooCommerce Subscriptions is not active on the site under test.' );
}

$site_host        = (string) wp_parse_url( (string) home_url(), PHP_URL_HOST );
$site_is_local    = in_array( $site_host, array( 'localhost', '127.0.0.1', '::1' ), true );
$any_site_allowed = isset( $args[1] ) && 'any-site' === $args[1];

if ( ! $site_is_local && ! $any_site_allowed ) {
	WP_CLI::error(
		sprintf(
			'The seed makes My Account the front page of %s, rebuilds its rewrite rules and creates a customer with a password this repository publishes. Set WP_E2E_ALLOW_ANY_SITE=1 to run it outside localhost.',
			$site_host
		)
	);
}

$customer_login = 'libresign_e2e_customer';
$customer_email = 'e2e-customer@libresign.test';
$product_sku    = 'LIBRESIGN-E2E-PLAN';

if ( '' === (string) get_option( 'permalink_structure' ) ) {
	update_option( 'permalink_structure', '/%postname%/' );
}

$account_page_id = (int) wc_get_page_id( 'myaccount' );

if ( $account_page_id <= 0 ) {
	WP_CLI::error( 'WooCommerce has no My Account page; install the WooCommerce pages first.' );
}

update_option( 'show_on_front', 'page' );
update_option( 'page_on_front', $account_page_id );

delete_option( 'libresign_root_my_account_rewrite_version' );

if ( '' === libresign_get_nextcloud_public_host() ) {
	update_option( 'nextcloud_public_host', 'https://nextcloud.libresign.test' );
}

$customer = get_user_by( 'login', $customer_login );

if ( $customer instanceof WP_User ) {
	$customer_id              = $customer->ID;
	$password_already_matches = wp_check_password( $customer_password, $customer->user_pass, $customer_id );

	if ( ! $password_already_matches ) {
		wp_set_password( $customer_password, $customer_id );
	}
} else {
	$customer_id = wp_insert_user(
		array(
			'user_login' => $customer_login,
			'user_email' => $customer_email,
			'user_pass'  => $customer_password,
			'first_name' => 'Ana',
			'last_name'  => 'Lima',
			'role'       => 'customer',
		)
	);

	if ( is_wp_error( $customer_id ) ) {
		WP_CLI::error( $customer_id->get_error_message() );
	}

	$customer_id = (int) $customer_id;
}

update_user_meta( $customer_id, 'billing_first_name', 'Ana' );
update_user_meta( $customer_id, 'billing_last_name', 'Lima' );
update_user_meta( $customer_id, 'billing_email', $customer_email );
update_user_meta( $customer_id, 'billing_country', 'BR' );

$product_id = (int) wc_get_product_id_by_sku( $product_sku );

if ( $product_id <= 0 ) {
	$new_product = new WC_Product_Subscription();
	$new_product->set_name( 'LibreSign E2E plan' );
	$new_product->set_slug( 'libresign-e2e-plan' );
	$new_product->set_sku( $product_sku );
	$new_product->set_status( 'publish' );
	$new_product->set_catalog_visibility( 'hidden' );
	$new_product->set_regular_price( '10' );
	$new_product->update_meta_data( '_subscription_price', '10' );
	$new_product->update_meta_data( '_subscription_period', 'month' );
	$new_product->update_meta_data( '_subscription_period_interval', '1' );
	$new_product->update_meta_data( '_subscription_length', '0' );
	$product_id = (int) $new_product->save();
}

foreach ( wcs_get_users_subscriptions( $customer_id ) as $subscription_of_a_previous_run ) {
	$subscription_of_a_previous_run->delete( true );
}

$subscription = wcs_create_subscription(
	array(
		'customer_id'      => $customer_id,
		'status'           => 'pending',
		'billing_period'   => 'month',
		'billing_interval' => 1,
		'start_date'       => gmdate( 'Y-m-d H:i:s', time() - MONTH_IN_SECONDS ),
	)
);

if ( is_wp_error( $subscription ) ) {
	WP_CLI::error( $subscription->get_error_message() );
}

$subscription->set_requires_manual_renewal( true );
$subscription->set_billing_first_name( 'Ana' );
$subscription->set_billing_last_name( 'Lima' );
$subscription->set_billing_email( $customer_email );
$subscription->add_product( wc_get_product( $product_id ), 1 );
$subscription->calculate_totals();
$subscription->save();
$subscription->update_status( 'active' );

WP_CLI::line(
	(string) wp_json_encode(
		array(
			'customerId'     => $customer_id,
			'customerLogin'  => $customer_login,
			'customerEmail'  => $customer_email,
			'productId'      => $product_id,
			'subscriptionId' => $subscription->get_id(),
			'accountPageId'  => $account_page_id,
			'nextcloudHost'  => libresign_get_nextcloud_public_host(),
		)
	)
);
