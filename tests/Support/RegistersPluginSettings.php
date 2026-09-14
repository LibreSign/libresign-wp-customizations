<?php
/**
 * Test helper for the settings the plugin registers on admin_init.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Support;

use Closure;
use ReflectionFunction;

/**
 * Runs only the plugin callbacks hooked on admin_init.
 *
 * The whole hook cannot be fired from a test because core sends headers there
 * and warns about being called outside wp-admin. Registering the settings from
 * a named function would make this helper unnecessary.
 */
trait RegistersPluginSettings {

	/**
	 * Register the plugin settings, with their sanitize callbacks.
	 *
	 * @return void
	 */
	protected function register_plugin_settings() {
		global $wp_filter;

		$plugin_file = dirname( __DIR__, 2 ) . '/libresign-wp-customizations.php';

		foreach ( $wp_filter['admin_init']->callbacks as $callbacks ) {
			foreach ( $callbacks as $callback ) {
				if ( ! $callback['function'] instanceof Closure ) {
					continue;
				}

				$declaration = new ReflectionFunction( $callback['function'] );

				if ( $declaration->getFileName() === $plugin_file ) {
					$declaration->invoke();
				}
			}
		}
	}
}
