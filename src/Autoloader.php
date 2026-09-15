<?php
/**
 * Class autoloader for the plugin.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations;

defined( 'ABSPATH' ) || exit;

/**
 * Maps LibreSign\WPCustomizations\* to src/*.php.
 *
 * The plugin is installed by cloning the repository, so Composer never runs on
 * the server and its autoloader does not exist at runtime.
 */
final class Autoloader {

	private const PREFIX = 'LibreSign\\WPCustomizations\\';

	public static function register(): void {
		spl_autoload_register( array( self::class, 'load' ) );
	}

	public static function load( string $class_name ): void {
		if ( 0 !== strpos( $class_name, self::PREFIX ) ) {
			return;
		}

		$file_path = __DIR__ . '/' . str_replace( '\\', '/', substr( $class_name, strlen( self::PREFIX ) ) ) . '.php';

		if ( is_readable( $file_path ) ) {
			require_once $file_path;
		}
	}
}
