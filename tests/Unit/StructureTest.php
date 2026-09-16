<?php
/**
 * Tests for the layout the suite is expected to follow.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit;

use LibreSign\WPCustomizations\Tests\Support\PluginFiles;
use PHPUnit\Framework\TestCase;

/**
 * Every file of the plugin is covered by the test named after it, and every
 * test covers a file that still exists.
 */
final class StructureTest extends TestCase {

	private const LAYOUT_TEST = 'tests/Unit/StructureTest.php';

	private const PLUGIN_FILE = 'libresign-wp-customizations.php';

	/**
	 * @dataProvider provide_plugin_files
	 *
	 * @param string $file Source file, relative to the root.
	 */
	public function test_a_file_of_the_plugin_is_covered_by_the_test_named_after_it( $file ) {
		$this->assert_one_exists( self::tests_covering( $file ), $file . ' is not covered by' );
	}

	/**
	 * @return iterable<string, array{0: string}>
	 */
	public static function provide_plugin_files() {
		$files = array_merge(
			array( self::PLUGIN_FILE ),
			PluginFiles::under( 'includes', '.php' ),
			PluginFiles::under( 'src', '.php' )
		);

		foreach ( $files as $file ) {
			yield $file => array( $file );
		}
	}

	/**
	 * @dataProvider provide_test_files
	 *
	 * @param string $file Test file, relative to the root.
	 */
	public function test_a_test_covers_a_file_of_the_plugin( $file ) {
		$this->assert_one_exists( self::files_covered_by( $file ), $file . ' does not cover' );
	}

	/**
	 * @return iterable<string, array{0: string}>
	 */
	public static function provide_test_files() {
		$files = array_merge(
			PluginFiles::under( 'tests/Unit', 'Test.php' ),
			PluginFiles::under( 'tests/Integration', 'Test.php' ),
			PluginFiles::under( 'tests/E2E', '.spec.ts' )
		);

		foreach ( $files as $file ) {
			if ( self::LAYOUT_TEST === $file ) {
				continue;
			}

			yield $file => array( $file );
		}
	}

	/**
	 * Tests allowed to cover a file, in the order the README describes them.
	 *
	 * @param string $file Source file, relative to the root.
	 * @return string[]
	 */
	private static function tests_covering( $file ) {
		if ( self::PLUGIN_FILE === $file ) {
			return array( 'tests/Integration/' . self::studly( basename( $file, '.php' ) ) . 'Test.php' );
		}

		if ( str_starts_with( $file, 'includes/' ) ) {
			return array( 'tests/Integration/Includes/' . self::studly( basename( $file, '.php' ) ) . 'Test.php' );
		}

		$name = substr( $file, strlen( 'src/' ), -strlen( '.php' ) );

		return array(
			'tests/Unit/' . $name . 'Test.php',
			'tests/Integration/' . $name . 'Test.php',
		);
	}

	/**
	 * Files a test is allowed to be named after.
	 *
	 * @param string $file Test file, relative to the root.
	 * @return string[]
	 */
	private static function files_covered_by( $file ) {
		if ( str_starts_with( $file, 'tests/E2E/' ) ) {
			return array( 'src/' . substr( $file, strlen( 'tests/E2E/' ), -strlen( '.spec.ts' ) ) . '.php' );
		}

		if ( str_starts_with( $file, 'tests/Unit/' ) ) {
			return array( 'src/' . substr( $file, strlen( 'tests/Unit/' ), -strlen( 'Test.php' ) ) . '.php' );
		}

		$name = substr( $file, strlen( 'tests/Integration/' ), -strlen( 'Test.php' ) );

		if ( str_starts_with( $name, 'Includes/' ) ) {
			return array( 'includes/' . self::kebab( substr( $name, strlen( 'Includes/' ) ) ) . '.php' );
		}

		return array(
			'src/' . $name . '.php',
			self::kebab( $name ) . '.php',
		);
	}

	/**
	 * @param string[] $files   Paths relative to the root, any of which settles it.
	 * @param string   $subject What the message is about.
	 */
	private function assert_one_exists( array $files, $subject ) {
		$found = array_filter(
			$files,
			static function ( $file ) {
				return file_exists( PluginFiles::root() . '/' . $file );
			}
		);

		$this->assertNotEmpty( $found, sprintf( '%s %s.', $subject, implode( ' or ', $files ) ) );
	}

	/**
	 * @param string $file_name File name in kebab case.
	 * @return string
	 */
	private static function studly( $file_name ) {
		return str_replace( ' ', '', ucwords( str_replace( '-', ' ', $file_name ) ) );
	}

	/**
	 * @param string $class_name Class name in studly case.
	 * @return string
	 */
	private static function kebab( $class_name ) {
		return strtolower( (string) preg_replace( '/(?<!^)[A-Z]/', '-$0', $class_name ) );
	}
}
