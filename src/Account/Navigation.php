<?php
/**
 * My Account navigation.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Account;

defined( 'ABSPATH' ) || exit;

/**
 * Which entries the customer sees, how they are named and which one is active.
 *
 * Every method takes the query vars of the request being rendered instead of
 * reading them, so none of this depends on the request.
 */
final class Navigation {

	/**
	 * Customer entries kept, in display order.
	 *
	 * @return string[]
	 */
	public static function order() {
		return array( 'subscriptions', 'orders', 'payment-methods', 'edit-account', 'customer-logout' );
	}

	/**
	 * Entries renamed because their meaning changed here.
	 *
	 * Whatever is left out keeps the WooCommerce label, and with it the
	 * translation WooCommerce already ships for every locale.
	 *
	 * @return array<string, string>
	 */
	public static function labels() {
		return array(
			'subscriptions'   => __( 'My subscription', 'libresign-wp-customizations' ),
			'orders'          => __( 'Invoices', 'libresign-wp-customizations' ),
			'payment-methods' => __( 'Billing', 'libresign-wp-customizations' ),
		);
	}

	/**
	 * Detail endpoints neither core nor Subscriptions highlights, mapped to their entry.
	 *
	 * @return array<string, string[]>
	 */
	public static function aliases() {
		return array(
			'subscriptions'   => array( 'subscription-payment-method' ),
			'payment-methods' => array( 'edit-address' ),
		);
	}

	/**
	 * Reorder and relabel the navigation, skipping unregistered endpoints.
	 *
	 * @param array<string, string> $items Navigation handed over by WooCommerce.
	 * @return array<string, string>
	 */
	public static function filter_items( array $items ) {
		$labels = self::labels();
		$menu   = array();

		foreach ( self::order() as $endpoint ) {
			if ( isset( $items[ $endpoint ] ) ) {
				$menu[ $endpoint ] = isset( $labels[ $endpoint ] ) ? $labels[ $endpoint ] : $items[ $endpoint ];
			}
		}

		return $menu;
	}

	/**
	 * Highlight the entry a detail screen belongs to.
	 *
	 * @param string[]             $classes    Classes of the entry.
	 * @param string               $endpoint   Endpoint of the entry.
	 * @param array<string, mixed> $query_vars Query vars of the request being rendered.
	 * @return string[]
	 */
	public static function filter_item_classes( array $classes, $endpoint, array $query_vars ) {
		if ( in_array( 'is-active', $classes, true ) ) {
			return $classes;
		}

		$aliases = self::aliases();

		if ( empty( $aliases[ $endpoint ] ) ) {
			return $classes;
		}

		foreach ( $aliases[ $endpoint ] as $alias ) {
			if ( isset( $query_vars[ $alias ] ) ) {
				$classes[] = 'is-active';
				break;
			}
		}

		return $classes;
	}

	/**
	 * Page title of an endpoint whose navigation label was renamed.
	 *
	 * @param string               $title      Title WooCommerce would use.
	 * @param string               $endpoint   Endpoint being rendered.
	 * @param array<string, mixed> $query_vars Query vars of the request being rendered.
	 * @return string
	 */
	public static function endpoint_title( $title, $endpoint, array $query_vars ) {
		$labels = self::labels();

		if ( ! isset( $labels[ $endpoint ] ) ) {
			return $title;
		}

		$page_number = isset( $query_vars[ $endpoint ] ) ? intval( $query_vars[ $endpoint ] ) : 0;

		if ( $page_number < 2 ) {
			return $labels[ $endpoint ];
		}

		return sprintf(
			/* translators: 1: navigation label, 2: page number */
			__( '%1$s (page %2$d)', 'libresign-wp-customizations' ),
			$labels[ $endpoint ],
			$page_number
		);
	}
}
