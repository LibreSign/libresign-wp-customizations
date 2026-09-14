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
 * the server and its autoloader is not available at runtime. The autoload
 * section of composer.json describes the same mapping for the tooling.
 */
final class Autoloader {

	private const PREFIX = 'LibreSign\\WPCustomizations\\';

	/**
	 * Start autoloading the plugin classes.
	 *
	 * @return void
	 */
	public static function register() {
		spl_autoload_register( array( self::class, 'load' ) );
	}

	/**
	 * Load a single class, ignoring everything outside the plugin namespace.
	 *
	 * @param string $class_name Fully qualified class name.
	 * @return void
	 */
	public static function load( $class_name ) {
		if ( 0 !== strpos( $class_name, self::PREFIX ) ) {
			return;
		}

		$path = __DIR__ . '/' . str_replace( '\\', '/', substr( $class_name, strlen( self::PREFIX ) ) ) . '.php';

		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
}
