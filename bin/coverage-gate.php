<?php
/**
 * Compares the coverage of the last run with the floor the repository keeps.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tools;

use SimpleXMLElement;

/*
 * The plugin is deployed by cloning the repository, so this directory is served
 * by the web server and nothing here runs outside the command line.
 */
if ( 'cli' !== PHP_SAPI && 'phpdbg' !== PHP_SAPI ) {
	exit;
}

/**
 * Reads the clover report of the suite and answers whether the floor still holds.
 *
 * A run above the floor fails as loudly as a run below it: the floor only ever
 * goes up, and a covered line that nothing keeps covered is lost silently.
 *
 * `--reset` drops the previous report, so a suite that runs without a coverage
 * driver writes nothing and is caught instead of graded on an older run.
 */
final class CoverageGate {

	private const REPORT = 'tests/.coverage/clover.xml';

	private const FLOOR = 'coverage-floor.txt';

	private const SLACK = 1.0;

	/**
	 * @param string   $root      Root of the repository.
	 * @param string[] $arguments Arguments the command was called with.
	 */
	public static function run( string $root, array $arguments ): int {
		$report = $root . '/' . self::REPORT;

		if ( in_array( '--reset', $arguments, true ) ) {
			return self::reset( $report );
		}

		if ( ! is_readable( $report ) ) {
			return self::fail(
				sprintf(
					'No coverage report at %s. The suite writes one only with a coverage driver enabled: XDEBUG_MODE=coverage, or pcov.',
					self::REPORT
				)
			);
		}

		$metrics = self::metrics( $report );

		if ( null === $metrics ) {
			return self::fail( sprintf( '%s is not a clover report.', self::REPORT ) );
		}

		$statements = (int) $metrics['statements'];

		if ( 0 === $statements ) {
			return self::fail( sprintf( '%s reports no line to cover.', self::REPORT ) );
		}

		$covered = floor( (int) $metrics['coveredstatements'] / $statements * 10000 ) / 100;
		$floor   = self::floor_of( $root );

		if ( null === $floor ) {
			return self::fail( sprintf( '%s does not hold a percentage.', self::FLOOR ) );
		}

		if ( $covered < $floor ) {
			return self::fail(
				sprintf(
					'Line coverage fell to %.2f%%, below the floor of %.2f%%. Cover what the change left uncovered.',
					$covered,
					$floor
				)
			);
		}

		if ( $covered >= $floor + self::SLACK ) {
			return self::fail(
				sprintf(
					'Line coverage rose to %.2f%%, above the floor of %.2f%%. Raise it: echo %.2f > %s',
					$covered,
					$floor,
					$covered,
					self::FLOOR
				)
			);
		}

		fwrite( STDOUT, sprintf( 'Line coverage: %.2f%% (floor %.2f%%).%s', $covered, $floor, PHP_EOL ) );

		return 0;
	}

	/**
	 * Drops the report of the previous run.
	 *
	 * @param string $report Path of the clover report.
	 */
	private static function reset( string $report ): int {
		if ( is_file( $report ) && ! unlink( $report ) ) {
			return self::fail( sprintf( 'Cannot remove the report of the previous run at %s.', self::REPORT ) );
		}

		return 0;
	}

	/**
	 * Totals of the whole report.
	 *
	 * @param string $report Path of the clover report.
	 */
	private static function metrics( string $report ): ?SimpleXMLElement {
		$coverage = simplexml_load_file( $report );

		if ( false === $coverage ) {
			return null;
		}

		$metrics = $coverage->xpath( '/coverage/project/metrics' );

		if ( empty( $metrics ) ) {
			return null;
		}

		return $metrics[0];
	}

	/**
	 * Percentage the repository does not go below.
	 *
	 * @param string $root Root of the repository.
	 */
	private static function floor_of( string $root ): ?float {
		$path = $root . '/' . self::FLOOR;

		if ( ! is_readable( $path ) ) {
			return null;
		}

		$floor = file_get_contents( $path );

		if ( false === $floor || ! is_numeric( trim( $floor ) ) ) {
			return null;
		}

		return (float) trim( $floor );
	}

	private static function fail( string $message ): int {
		fwrite( STDERR, $message . PHP_EOL );

		return 1;
	}
}

exit( (int) CoverageGate::run( dirname( __DIR__ ), array_slice( $argv, 1 ) ) );
