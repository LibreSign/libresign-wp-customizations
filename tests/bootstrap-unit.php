<?php
/**
 * PHPUnit bootstrap for the unit suite: loads the plugin without WordPress.
 *
 * @package LibreSign_WP_Customizations
 */

$libresign_autoload = dirname( __DIR__ ) . '/vendor/autoload.php';

if ( ! file_exists( $libresign_autoload ) ) {
	echo 'Error: run `composer install` before running the tests.' . PHP_EOL;
	exit( 1 );
}

require_once $libresign_autoload;

/*
 * The plugin refuses to load outside WordPress and registers its hooks while
 * the file is read. The unit suite only exercises functions that decide over
 * their own arguments, so the few WordPress functions reached along the way
 * answer here and no WordPress is loaded.
 */
define( 'ABSPATH', dirname( __DIR__ ) . '/' );

/**
 * Hook registration, which the unit suite never inspects.
 */
function add_action() {}

/**
 * Filter registration, which the unit suite never inspects.
 */
function add_filter() {}

/**
 * Path of a plugin file relative to the plugins directory.
 *
 * @param string $file Absolute path to the file.
 * @return string
 */
function plugin_basename( $file ) {
	return basename( dirname( $file ) ) . '/' . basename( $file );
}

/**
 * JSON encoding, which WordPress only wraps to pick its own default flags.
 *
 * @param mixed $data Value to encode.
 * @return string|false
 */
function wp_json_encode( $data ) {
	return json_encode( $data );
}

/**
 * Translation, which without a text domain loaded returns the original string.
 *
 * @param string $text Text to translate.
 * @return string
 */
function __( $text ) {
	return $text;
}

require_once dirname( __DIR__ ) . '/libresign-wp-customizations.php';
