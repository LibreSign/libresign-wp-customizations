<?php
/**
 * Test helper for the settings the plugin registers on admin_init.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Support;

/**
 * Registers the plugin settings without firing admin_init.
 *
 * The whole hook cannot be fired from a test because core sends headers there
 * and warns about being called outside wp-admin.
 */
trait RegistersPluginSettings {

	/**
	 * Register the plugin settings, with their sanitize callbacks.
	 *
	 * @return void
	 */
	protected function register_plugin_settings() {
		libresign_register_settings();
	}
}
