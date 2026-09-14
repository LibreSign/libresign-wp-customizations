<?php
/**
 * Tests for recognizing the run that publishes the site.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\SiteDeploy;
use LibreSign\WPCustomizations\Github\WorkflowRun;
use PHPUnit\Framework\TestCase;

/**
 * Only one run out of everything GitHub reports puts the site live.
 */
final class SiteDeployTest extends TestCase {

	/**
	 * The deploy as configured in production.
	 *
	 * @return SiteDeploy
	 */
	private static function site_deploy() {
		return new SiteDeploy( 'LibreSign/site', 'gh-pages', 'pages build and deployment' );
	}

	/**
	 * Payload of a production deploy, with the given fields replaced.
	 *
	 * @param array<string, mixed> $overrides Values replacing the defaults.
	 * @return WorkflowRun
	 */
	private static function production_run( array $overrides = array() ) {
		return WorkflowRun::from_payload(
			array_replace_recursive(
				array(
					'action'       => 'completed',
					'repository'   => array( 'full_name' => 'LibreSign/site' ),
					'workflow_run' => array(
						'name'        => 'pages build and deployment',
						'conclusion'  => 'success',
						'head_branch' => 'gh-pages',
					),
				),
				$overrides
			)
		);
	}

	public function test_the_production_deploy_is_recognized() {
		$this->assertTrue( self::site_deploy()->is_production_run( self::production_run() ) );
	}

	public function test_the_workflow_name_may_come_from_the_workflow_instead_of_the_run() {
		$run = WorkflowRun::from_payload(
			array(
				'action'       => 'completed',
				'repository'   => array( 'full_name' => 'LibreSign/site' ),
				'workflow'     => array( 'name' => 'pages build and deployment' ),
				'workflow_run' => array(
					'conclusion'  => 'success',
					'head_branch' => 'gh-pages',
				),
			)
		);

		$this->assertTrue( self::site_deploy()->is_production_run( $run ) );
	}

	/**
	 * @dataProvider provide_other_runs
	 *
	 * @param array<string, mixed> $overrides Values replacing the production defaults.
	 */
	public function test_any_other_run_is_not_the_production_deploy( $overrides ) {
		$this->assertFalse( self::site_deploy()->is_production_run( self::production_run( $overrides ) ) );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>}>
	 */
	public static function provide_other_runs() {
		yield 'another repository'    => array( array( 'repository' => array( 'full_name' => 'LibreSign/libresign' ) ) );
		yield 'the run is starting'   => array( array( 'action' => 'requested' ) );
		yield 'the run is in progress' => array( array( 'action' => 'in_progress' ) );
		yield 'the run failed'        => array( array( 'workflow_run' => array( 'conclusion' => 'failure' ) ) );
		yield 'the run was cancelled' => array( array( 'workflow_run' => array( 'conclusion' => 'cancelled' ) ) );
		yield 'another branch'        => array( array( 'workflow_run' => array( 'head_branch' => 'main' ) ) );
		yield 'another workflow'      => array( array( 'workflow_run' => array( 'name' => 'tests' ) ) );
	}

	public function test_the_expected_run_is_the_configured_one() {
		$deploy = new SiteDeploy( 'LibreSign/staging', 'main', 'deploy' );

		$this->assertFalse( $deploy->is_production_run( self::production_run() ) );
		$this->assertTrue(
			$deploy->is_production_run(
				self::production_run(
					array(
						'repository'   => array( 'full_name' => 'LibreSign/staging' ),
						'workflow_run' => array(
							'name'        => 'deploy',
							'head_branch' => 'main',
						),
					)
				)
			)
		);
	}
}
