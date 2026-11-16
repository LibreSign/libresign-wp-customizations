<?php
/**
 * PHPUnit bootstrap: boots WordPress and loads the plugin into it.
 *
 * @package LibreSign_WP_Customizations
 */

/*
 * The plugin is deployed by cloning the repository, so this directory is served
 * by the web server. Running the WordPress test bootstrap over HTTP installs
 * the test suite, which drops every table of the test database, so nothing here
 * runs outside the command line.
 */
if ( 'cli' !== PHP_SAPI && 'phpdbg' !== PHP_SAPI ) {
	exit;
}

$libresign_autoload = dirname( __DIR__ ) . '/vendor/autoload.php';

if ( ! file_exists( $libresign_autoload ) ) {
	echo 'Error: run `composer install` before running the tests.' . PHP_EOL;
	exit( 1 );
}

require_once $libresign_autoload;

define( 'WP_TESTS_PHPUNIT_POLYFILLS_PATH', dirname( __DIR__ ) . '/vendor/yoast/phpunit-polyfills' );

putenv( 'WP_PHPUNIT__TESTS_CONFIG=' . __DIR__ . '/wp-tests-config.php' );

$libresign_wp_phpunit_dir = getenv( 'WP_PHPUNIT__DIR' );

if ( false === $libresign_wp_phpunit_dir || '' === $libresign_wp_phpunit_dir ) {
	$libresign_wp_phpunit_dir = dirname( __DIR__ ) . '/vendor/wp-phpunit/wp-phpunit';
}

require_once $libresign_wp_phpunit_dir . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	static function () {
		require dirname( __DIR__ ) . '/libresign-wp-customizations.php';
	}
);

/*
 * No test is allowed to reach the network. A test that exercises an outgoing
 * request stubs it with its own pre_http_request filter, which is registered
 * later and therefore replaces this one.
 */
tests_add_filter(
	'pre_http_request',
	static function ( $preempt, $args, $url ) {
		return new WP_Error(
			'libresign_tests_http_blocked',
			sprintf( 'Unexpected HTTP request to %s. Stub it with the pre_http_request filter.', $url )
		);
	},
	10,
	3
);

require $libresign_wp_phpunit_dir . '/includes/bootstrap.php';
