<?php

defined( 'ABSPATH' ) || exit;

function libresign_e2e_add_saved_payment_methods_gateway( $gateways ) {
	$gateways[] = 'Libresign_E2E_Saved_Payment_Methods_Gateway';

	return $gateways;
}

function libresign_e2e_define_saved_payment_methods_gateway() {
	if ( ! class_exists( 'WC_Payment_Gateway' ) || class_exists( 'Libresign_E2E_Saved_Payment_Methods_Gateway' ) ) {
		return;
	}

	class Libresign_E2E_Saved_Payment_Methods_Gateway extends WC_Payment_Gateway {

		public function __construct() {
			$this->id           = 'libresign_e2e_saved_payment_methods';
			$this->method_title = 'LibreSign E2E saved payment methods';
			$this->title        = 'LibreSign E2E saved payment methods';
			$this->has_fields   = false;
			$this->enabled      = 'yes';
			$this->supports     = array( 'products', 'tokenization', 'add_payment_method' );
		}
	}

	add_filter( 'woocommerce_payment_gateways', 'libresign_e2e_add_saved_payment_methods_gateway' );
}
add_action( 'plugins_loaded', 'libresign_e2e_define_saved_payment_methods_gateway' );
