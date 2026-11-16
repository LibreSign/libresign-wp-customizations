<?php
/**
 * Subscription status changes that ask for a confirmation.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Subscription;

defined( 'ABSPATH' ) || exit;

final class StatusChange {

	/**
	 * @return array{question: string, confirm: string, dismiss: string}|null
	 */
	public static function confirmation_strings( string $new_status ): ?array {
		$strings = array(
			'cancelled' => array(
				'question' => __( 'Are you sure you want to cancel your subscription? This action cannot be undone.', 'libresign-wp-customizations' ),
				'confirm'  => __( 'Yes, cancel subscription', 'libresign-wp-customizations' ),
				'dismiss'  => __( 'No, keep subscription', 'libresign-wp-customizations' ),
			),
			'active'    => array(
				'question' => __( 'Are you sure you want to reactivate your subscription?', 'libresign-wp-customizations' ),
				'confirm'  => __( 'Yes, reactivate subscription', 'libresign-wp-customizations' ),
				'dismiss'  => __( 'No, go back', 'libresign-wp-customizations' ),
			),
		);

		return $strings[ $new_status ] ?? null;
	}
}
