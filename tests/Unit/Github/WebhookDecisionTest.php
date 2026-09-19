<?php
/**
 * Tests for what to do with a webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\WebhookDecision;
use LibreSign\WPCustomizations\Github\WorkflowRun;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * The four answers a delivery can get, and what each one carries.
 */
final class WebhookDecisionTest extends TestCase {

	/**
	 * @dataProvider provide_decisions
	 *
	 * @param WebhookDecision $decision Answer to a delivery.
	 * @param string          $outcome  The only question answered with true.
	 */
	public function test_a_decision_is_of_a_single_kind( WebhookDecision $decision, $outcome ) {
		$this->assertSame( 'reject' === $outcome, $decision->is_rejected() );
		$this->assertSame( 'pong' === $outcome, $decision->is_pong() );
		$this->assertSame( 'ignore' === $outcome, $decision->is_ignored() );
		$this->assertSame( 'deploy' === $outcome, $decision->is_deploy() );
	}

	/**
	 * @return iterable<string, array{0: WebhookDecision, 1: string}>
	 */
	public static function provide_decisions() {
		yield 'a delivery that is turned down' => array( WebhookDecision::reject( 'libresign_invalid_signature', 'Invalid signature.', 401 ), 'reject' );
		yield 'the ping GitHub sends first'    => array( WebhookDecision::pong(), 'pong' );
		yield 'a delivery not worth acting on' => array( WebhookDecision::ignore( 'not_the_site_repository' ), 'ignore' );
		yield 'a deploy of the site'           => array( WebhookDecision::deploy( WorkflowRun::from_payload( array() ) ), 'deploy' );
	}

	public function test_a_rejection_carries_the_error_the_endpoint_answers() {
		$decision = WebhookDecision::reject( 'libresign_invalid_signature', 'Invalid signature.', 401 );

		$this->assertSame( 'libresign_invalid_signature', $decision->code() );
		$this->assertSame( 'Invalid signature.', $decision->message() );
		$this->assertSame( 401, $decision->status() );
	}

	public function test_an_ignored_delivery_reports_the_reason_first() {
		$decision = WebhookDecision::ignore(
			'not_the_site_repository',
			array(
				'repository' => 'LibreSign/libresign',
				'expected'   => 'LibreSign/site',
			)
		);

		$this->assertSame(
			array(
				'reason'     => 'not_the_site_repository',
				'repository' => 'LibreSign/libresign',
				'expected'   => 'LibreSign/site',
			),
			$decision->data()
		);
	}

	public function test_a_deploy_carries_the_run_that_published_the_site() {
		$workflow_run = WorkflowRun::from_payload( array( 'repository' => array( 'full_name' => 'LibreSign/site' ) ) );

		$this->assertSame( $workflow_run, WebhookDecision::deploy( $workflow_run )->workflow_run() );
	}

	/**
	 * @dataProvider provide_decisions_without_a_run
	 *
	 * @param WebhookDecision $decision Answer to a delivery.
	 */
	public function test_only_a_deploy_carries_a_workflow_run( WebhookDecision $decision ) {
		$this->expectException( LogicException::class );

		$decision->workflow_run();
	}

	/**
	 * @return iterable<string, array{0: WebhookDecision}>
	 */
	public static function provide_decisions_without_a_run() {
		yield 'a delivery that is turned down' => array( WebhookDecision::reject( 'libresign_invalid_signature', 'Invalid signature.', 401 ) );
		yield 'the ping GitHub sends first'    => array( WebhookDecision::pong() );
		yield 'a delivery not worth acting on' => array( WebhookDecision::ignore( 'not_the_site_repository' ) );
	}
}
