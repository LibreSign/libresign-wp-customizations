<?php
/**
 * Test helper listing the files the plugin is made of.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Support;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Walks the repository so the conventions between src, includes and tests are
 * read from the files themselves instead of from a list kept by hand.
 */
final class PluginFiles {

	/**
	 * Root of the repository.
	 *
	 * @return string
	 */
	public static function root() {
		return dirname( __DIR__, 2 );
	}

	/**
	 * Files under a directory of the repository, relative to its root and sorted.
	 *
	 * @param string $directory Path relative to the root, such as `src`.
	 * @param string $suffix    End of the file name, such as `Test.php`.
	 * @return string[]
	 */
	public static function under( $directory, $suffix ) {
		$root = self::root() . '/' . $directory;

		if ( ! is_dir( $root ) ) {
			return array();
		}

		$paths = array();

		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
		);

		/** @var SplFileInfo $file */
		foreach ( $files as $file ) {
			$path = str_replace( '\\', '/', $file->getPathname() );

			if ( ! $file->isFile() || ! str_ends_with( $path, $suffix ) ) {
				continue;
			}

			$paths[] = substr( $path, strlen( self::root() ) + 1 );
		}

		sort( $paths );

		return $paths;
	}
}
