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

		$this->assertContains( array( Autoloader::class, 'load' ), spl_autoload_functions() );
	}

	/**
	 * The suite runs under the Composer autoloader, which maps the same prefix,
	 * so this is the only test that can tell whether the plugin would load its
	 * own classes on a server where Composer never ran.
	 */
	public function test_every_class_is_loaded_with_no_other_autoloader_in_the_stack() {
		$expected = array();

		foreach ( PluginFiles::under( 'src', '.php' ) as $file ) {
			$expected[ self::class_name_of( $file ) ] = PluginFiles::root() . '/' . $file;
		}

		$command = array_merge(
			array( PHP_BINARY, PluginFiles::root() . '/tests/Support/autoloader-probe.php' ),
			array_keys( $expected )
		);

		$output = array();
		$status = 0;
		exec( implode( ' ', array_map( 'escapeshellarg', $command ) ), $output, $status );

		$this->assertSame( 0, $status, implode( PHP_EOL, $output ) );
		$this->assertSame( $expected, json_decode( implode( '', $output ), true ) );
	}

	/**
	 * @dataProvider provide_plugin_classes
	 *
	 * @param string $class_name Class of the plugin.
	 * @param string $file       File it is declared in, relative to the root.
	 */
	public function test_a_class_is_loaded_from_the_file_named_after_it( $class_name, $file ) {
		Autoloader::load( $class_name );

		$this->assertSame( PluginFiles::root() . '/' . $file, ( new ReflectionClass( $class_name ) )->getFileName() );
	}

	/**
	 * @return iterable<string, array{0: string, 1: string}>
	 */
	public static function provide_plugin_classes() {
		foreach ( PluginFiles::under( 'src', '.php' ) as $file ) {
			yield $file => array( self::class_name_of( $file ), $file );
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

	/**
	 * @param string $file File of `src`, relative to the root.
	 * @return string
	 */
	private static function class_name_of( $file ) {
		return 'LibreSign\\WPCustomizations\\' . str_replace( '/', '\\', substr( $file, strlen( 'src/' ), -strlen( '.php' ) ) );
	}
}
