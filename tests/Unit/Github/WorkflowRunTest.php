<?php
/**
 * Tests for the workflow run described by a webhook payload.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\WorkflowRun;
use PHPUnit\Framework\TestCase;

/**
 * Reading a payload GitHub may have filled in only partially.
 */
final class WorkflowRunTest extends TestCase {

	public function test_reads_the_fields_the_deploy_reports() {
		$run = WorkflowRun::from_payload(
			array(
				'action'       => 'completed',
				'repository'   => array( 'full_name' => 'LibreSign/site' ),
				'workflow_run' => array(
					'name'        => 'pages build and deployment',
					'conclusion'  => 'success',
					'head_branch' => 'gh-pages',
					'head_sha'    => '0f1e2d3',
					'html_url'    => 'https://github.com/LibreSign/site/actions/runs/1',
					'updated_at'  => '2026-09-14T12:00:00Z',
				),
			)
		);

		$this->assertSame( 'LibreSign/site', $run->repository() );
		$this->assertSame( 'completed', $run->action() );
		$this->assertSame( 'success', $run->conclusion() );
		$this->assertSame( 'gh-pages', $run->head_branch() );
		$this->assertSame( '0f1e2d3', $run->head_sha() );
		$this->assertSame( 'https://github.com/LibreSign/site/actions/runs/1', $run->html_url() );
		$this->assertSame( '2026-09-14T12:00:00Z', $run->updated_at() );
		$this->assertSame( 'pages build and deployment', $run->workflow_name() );
	}

	public function test_an_empty_payload_answers_every_field_with_an_empty_string() {
		$run = WorkflowRun::from_payload( array() );

		$this->assertSame( '', $run->repository() );
		$this->assertSame( '', $run->action() );
		$this->assertSame( '', $run->conclusion() );
		$this->assertSame( '', $run->head_branch() );
		$this->assertSame( '', $run->head_sha() );
		$this->assertSame( '', $run->html_url() );
		$this->assertSame( '', $run->updated_at() );
		$this->assertSame( '', $run->workflow_name() );
	}

	/**
	 * @dataProvider provide_payloads
	 *
	 * @param array<string, mixed> $payload  Parsed webhook payload.
	 * @param string               $expected Expected workflow name.
	 */
	public function test_workflow_name( $payload, $expected ) {
		$this->assertSame( $expected, WorkflowRun::from_payload( $payload )->workflow_name() );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>, 1: string}>
	 */
	public static function provide_payloads() {
		yield 'the run name wins' => array(
			array(
				'workflow_run' => array( 'name' => 'pages build and deployment' ),
				'workflow'     => array( 'name' => 'deploy' ),
			),
			'pages build and deployment',
		);
		yield 'falls back to the workflow name' => array(
			array( 'workflow' => array( 'name' => 'deploy' ) ),
			'deploy',
		);
		yield 'a blank run name falls back too' => array(
			array(
				'workflow_run' => array( 'name' => '   ' ),
				'workflow'     => array( 'name' => 'deploy' ),
			),
			'deploy',
		);
		yield 'names are trimmed' => array(
			array( 'workflow_run' => array( 'name' => "  deploy \n" ) ),
			'deploy',
		);
		yield 'neither is present' => array( array( 'action' => 'completed' ), '' );
		yield 'an empty payload'   => array( array(), '' );
	}

	/**
	 * @dataProvider provide_unexpected_shapes
	 *
	 * @param array<string, mixed> $payload Payload in a shape GitHub does not send.
	 */
	public function test_a_field_that_is_not_a_string_is_read_as_empty( $payload ) {
		$this->assertSame( '', WorkflowRun::from_payload( $payload )->head_branch() );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>}>
	 */
	public static function provide_unexpected_shapes() {
		yield 'the run is not an array'   => array( array( 'workflow_run' => 'gh-pages' ) );
		yield 'the branch is an array'    => array( array( 'workflow_run' => array( 'head_branch' => array( 'gh-pages' ) ) ) );
		yield 'the branch is null'        => array( array( 'workflow_run' => array( 'head_branch' => null ) ) );
		yield 'the run key is missing'    => array( array( 'repository' => array( 'full_name' => 'LibreSign/site' ) ) );
	}
}
