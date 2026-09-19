<?php
/**
 * My Account navigation customizations.
 *
 * Reorders and relabels the WooCommerce My Account navigation, keeps the
 * endpoint page titles in sync with those labels, and merges the addresses
 * screen into the billing screen.
 *
 * @package LibreSign_WP_Customizations
 */

use LibreSign\WPCustomizations\Account\Navigation;

defined( 'ABSPATH' ) || exit;

/**
 * Query vars of the request currently being rendered.
 */
function libresign_get_current_query_vars() {
    global $wp;

    return isset( $wp->query_vars ) ? $wp->query_vars : array();
}

/**
 * Reorder and relabel the My Account navigation, skipping unregistered endpoints.
 */
function libresign_filter_account_menu_items( $items ) {
    return Navigation::filter_items( (array) $items );
}
add_filter( 'woocommerce_account_menu_items', 'libresign_filter_account_menu_items', 20 );

/**
 * Highlight the navigation entry a detail screen belongs to.
 */
function libresign_filter_account_menu_item_classes( $classes, $endpoint ) {
    return Navigation::filter_item_classes( (array) $classes, $endpoint, libresign_get_current_query_vars() );
}
add_filter( 'woocommerce_account_menu_item_classes', 'libresign_filter_account_menu_item_classes', 10, 2 );

/**
 * Page title of an endpoint whose navigation label was renamed.
 */
function libresign_filter_account_endpoint_title( $title, $endpoint ) {
    return Navigation::endpoint_title( $title, $endpoint, libresign_get_current_query_vars() );
}

/**
 * Page title for a single invoice.
 */
function libresign_filter_view_order_endpoint_title( $title ) {
    $query_vars = libresign_get_current_query_vars();

    if ( ! isset( $query_vars['view-order'] ) ) {
        return $title;
    }

    $order = wc_get_order( $query_vars['view-order'] );

    if ( ! $order ) {
        return $title;
    }

    /* translators: %s: order number */
    return sprintf( __( 'Invoice #%s', 'libresign-wp-customizations' ), $order->get_order_number() );
}

/**
 * Keep the endpoint page titles in sync with the navigation labels.
 */
function libresign_register_account_endpoint_titles() {
    foreach ( array_keys( Navigation::labels() ) as $endpoint ) {
        add_filter( 'woocommerce_endpoint_' . $endpoint . '_title', 'libresign_filter_account_endpoint_title', 20, 2 );
    }

    add_filter( 'woocommerce_endpoint_view-order_title', 'libresign_filter_view_order_endpoint_title', 20 );
}
add_action( 'init', 'libresign_register_account_endpoint_titles' );

/**
 * Section heading for a block merged into the billing screen.
 */
function libresign_render_account_section_title( $title ) {
    printf(
        '<h2 class="libresign-account-section-title">%s</h2>',
        esc_html( $title )
    );
}

/**
 * Heading for the payment methods table on the billing screen.
 */
function libresign_render_payment_methods_section_title() {
    libresign_render_account_section_title( __( 'Payment methods', 'libresign-wp-customizations' ) );
}
add_action( 'woocommerce_before_account_payment_methods', 'libresign_render_payment_methods_section_title', 5 );

/**
 * Render the addresses after the whole payment methods template, button included.
 */
function libresign_render_addresses_on_payment_methods() {
    libresign_render_account_section_title( __( 'Addresses', 'libresign-wp-customizations' ) );

    wc_get_template( 'myaccount/my-address.php' );
}
add_action( 'woocommerce_account_payment-methods_endpoint', 'libresign_render_addresses_on_payment_methods', 20 );

/**
 * Send the standalone addresses list to the billing screen it was merged into.
 */
function libresign_redirect_addresses_to_billing() {
    if ( ! function_exists( 'is_account_page' ) || ! is_account_page() ) {
        return;
    }

    $query_vars        = libresign_get_current_query_vars();
    $is_addresses_list = isset( $query_vars['edit-address'] ) && '' === $query_vars['edit-address'];

    if ( ! $is_addresses_list ) {
        return;
    }

    wp_safe_redirect( wc_get_endpoint_url( 'payment-methods', '', wc_get_page_permalink( 'myaccount' ) ) );
    exit;
}
add_action( 'template_redirect', 'libresign_redirect_addresses_to_billing' );

/**
 * Describe the addresses in terms of the subscription instead of a checkout.
 */
function libresign_filter_my_address_description() {
    return esc_html__( 'These addresses are used on your invoices and subscription charges.', 'libresign-wp-customizations' );
}
add_filter( 'woocommerce_my_account_my_address_description', 'libresign_filter_my_address_description' );
