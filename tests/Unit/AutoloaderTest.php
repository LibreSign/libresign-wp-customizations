<?php
/**
 * Tests for the class autoloader of the plugin.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit;

use LibreSign\WPCustomizations\Autoloader;
use LibreSign\WPCustomizations\Tests\Support\PluginFiles;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * The plugin is installed by cloning the repository, so this is the only
 * autoloader it has on the server.
 */
final class AutoloaderTest extends TestCase {

	public function test_registering_puts_the_plugin_loader_in_the_stack() {
		Autoloader::register();
		$autoloaders = spl_autoload_functions();
		spl_autoload_unregister( array( Autoloader::class, 'load' ) );

		$this->assertContains( array( Autoloader::class, 'load' ), $autoloaders );
	}

	/**
	 * @dataProvider provide_plugin_classes
	 *
	 * @param string $class_name Class of the plugin.
	 * @param string $file       File it is declared in, relative to the root.
	 */
	public function test_a_class_is_loaded_from_the_file_named_after_it( $class_name, $file ) {
		Autoloader::load( $class_name );

		$this->assertTrue( class_exists( $class_name, false ), $class_name . ' was not loaded from ' . $file . '.' );
		$this->assertSame( PluginFiles::root() . '/' . $file, ( new ReflectionClass( $class_name ) )->getFileName() );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string}>
	 */
	public static function provide_plugin_classes() {
		foreach ( PluginFiles::under( 'src', '.php' ) as $file ) {
			$class_name = 'LibreSign\\WPCustomizations\\' . str_replace( '/', '\\', substr( $file, strlen( 'src/' ), -strlen( '.php' ) ) );

			yield $file => array( $class_name, $file );
		}
	}

	public function test_a_class_of_another_project_is_left_to_its_own_autoloader() {
		Autoloader::load( 'Acme\\Widgets\\Thing' );

		$this->assertFalse( class_exists( 'Acme\\Widgets\\Thing', false ) );
	}

	public function test_a_class_the_plugin_does_not_have_is_not_an_error() {
		Autoloader::load( 'LibreSign\\WPCustomizations\\Github\\NotAFile' );

		$this->assertFalse( class_exists( 'LibreSign\\WPCustomizations\\Github\\NotAFile', false ) );
	}
}
