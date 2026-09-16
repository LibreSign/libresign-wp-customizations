<?php
/**
 * Test helper answering which file each class was loaded from.
 *
 * Run as its own process, with the plugin autoloader as the only one in the
 * stack, which is the situation on a server where Composer never ran. It takes
 * the class names as arguments and answers a JSON object of class to file, with
 * an empty string for a class it could not load.
 *
 * @package LibreSign_WP_Customizations
 */

if ( 'cli' !== PHP_SAPI ) {
	exit;
}

define( 'ABSPATH', __DIR__ . '/' );

require dirname( __DIR__, 2 ) . '/src/Autoloader.php';

LibreSign\WPCustomizations\Autoloader::register();

$libresign_loaded_from = array();

foreach ( array_slice( $argv, 1 ) as $libresign_class_name ) {
	$libresign_loaded_from[ $libresign_class_name ] = class_exists( $libresign_class_name )
		? ( new ReflectionClass( $libresign_class_name ) )->getFileName()
		: '';
}

fwrite( STDOUT, (string) json_encode( $libresign_loaded_from ) );
