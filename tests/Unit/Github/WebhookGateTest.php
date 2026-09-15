<?php
/**
 * Tests for the inspection of a webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Unit\Github;

use LibreSign\WPCustomizations\Github\SiteDeploy;
use LibreSign\WPCustomizations\Github\WebhookGate;
use LibreSign\WPCustomizations\Github\WebhookRequest;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * Every answer the endpoint can give, decided without a request or a database.
 */
final class WebhookGateTest extends TestCase {

	private const SECRET = 'webhook-secret';

	/**
	 * Payload of a production deploy, with the given fields replaced.
	 *
	 * @param array<string, mixed> $overrides Values replacing the defaults.
	 * @return string
	 */
	private static function production_payload( array $overrides = array() ) {
		return (string) wp_json_encode(
			array_replace_recursive(
				array(
					'action'       => 'completed',
					'repository'   => array( 'full_name' => 'LibreSign/site' ),
					'workflow_run' => array(
						'name'        => 'pages build and deployment',
						'conclusion'  => 'success',
						'head_branch' => 'gh-pages',
						'head_sha'    => '0f1e2d3',
					),
				),
				$overrides
			)
		);
	}

	/**
	 * The gate as configured in production.
	 *
	 * @param string $secret Secret shared with the repository webhook.
	 * @return WebhookGate
	 */
	private static function gate( $secret = self::SECRET ) {
		return new WebhookGate(
			$secret,
			new SiteDeploy( 'LibreSign/site', 'gh-pages', 'pages build and deployment' )
		);
	}

	/**
	 * A delivery signed with the secret.
	 *
	 * @param string $event X-GitHub-Event header.
	 * @param string $body  Raw request body.
	 * @return WebhookRequest
	 */
	private static function signed_delivery( $event, $body ) {
		return new WebhookRequest(
			'GitHub-Hookshot/044aadd',
			$event,
			'sha256=' . hash_hmac( 'sha256', $body, self::SECRET ),
			'delivery-1',
			$body
		);
	}

	public function test_an_unconfigured_secret_makes_the_endpoint_unavailable() {
		$decision = self::gate( '' )->decide( self::signed_delivery( 'ping', '{}' ) );

		$this->assertTrue( $decision->is_rejected() );
		$this->assertSame( 'libresign_github_webhook_secret_missing', $decision->code() );
		$this->assertSame( 503, $decision->status() );
	}

	public function test_a_blank_secret_makes_the_endpoint_unavailable() {
		$decision = self::gate( '   ' )->decide( self::signed_delivery( 'ping', '{}' ) );

		$this->assertSame( 'libresign_github_webhook_secret_missing', $decision->code() );
	}

	public function test_a_request_from_another_client_is_rejected() {
		$decision = self::gate()->decide( new WebhookRequest( 'curl/8.7.1', 'ping', '', 'delivery-1', '{}' ) );

		$this->assertTrue( $decision->is_rejected() );
		$this->assertSame( 'libresign_github_webhook_invalid_agent', $decision->code() );
		$this->assertSame( 403, $decision->status() );
	}

	public function test_a_wrongly_signed_request_is_rejected() {
		$decision = self::gate()->decide(
			new WebhookRequest(
				'GitHub-Hookshot/044aadd',
				'ping',
				'sha256=' . hash_hmac( 'sha256', '{}', 'another-secret' ),
				'delivery-1',
				'{}'
			)
		);

		$this->assertTrue( $decision->is_rejected() );
		$this->assertSame( 'libresign_github_webhook_invalid_signature', $decision->code() );
		$this->assertSame( 403, $decision->status() );
	}

	public function test_the_client_is_checked_before_the_signature() {
		$decision = self::gate()->decide( new WebhookRequest( 'curl/8.7.1', 'ping', 'sha256=deadbeef', 'delivery-1', '{}' ) );

		$this->assertSame( 'libresign_github_webhook_invalid_agent', $decision->code() );
	}

	public function test_a_ping_is_answered() {
		$decision = self::gate()->decide( self::signed_delivery( 'ping', '{"zen":"Design for failure."}' ) );

		$this->assertTrue( $decision->is_pong() );
	}

	public function test_another_event_is_ignored() {
		$decision = self::gate()->decide( self::signed_delivery( 'push', '{"ref":"refs/heads/main"}' ) );

		$this->assertTrue( $decision->is_ignored() );
		$this->assertSame(
			array(
				'reason' => 'unsupported_event',
				'event'  => 'push',
			),
			$decision->data()
		);
	}

	public function test_a_body_that_is_not_json_is_rejected() {
		$decision = self::gate()->decide( self::signed_delivery( 'workflow_run', 'not json' ) );

		$this->assertTrue( $decision->is_rejected() );
		$this->assertSame( 'libresign_github_webhook_invalid_payload', $decision->code() );
		$this->assertSame( 400, $decision->status() );
	}

	/**
	 * @dataProvider provide_non_production_payloads
	 *
	 * @param array<string, mixed>  $overrides Values replacing the production defaults.
	 * @param array<string, string> $reported_details  Details expected in the answer.
	 */
	public function test_a_run_that_is_not_the_production_deploy_is_ignored( $overrides, $reported_details ) {
		$decision = self::gate()->decide( self::signed_delivery( 'workflow_run', self::production_payload( $overrides ) ) );

		$this->assertTrue( $decision->is_ignored() );
		$this->assertSame( array_merge( array( 'reason' => 'not_production_deploy' ), $reported_details ), $decision->data() );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>, 1: array<string, string>}>
	 */
	public static function provide_non_production_payloads() {
		yield 'another repository' => array(
			array( 'repository' => array( 'full_name' => 'LibreSign/libresign' ) ),
			array(
				'repository'    => 'LibreSign/libresign',
				'workflow_name' => 'pages build and deployment',
				'head_branch'   => 'gh-pages',
				'conclusion'    => 'success',
			),
		);
		yield 'the run is starting' => array(
			array( 'action' => 'requested' ),
			array(
				'repository'    => 'LibreSign/site',
				'workflow_name' => 'pages build and deployment',
				'head_branch'   => 'gh-pages',
				'conclusion'    => 'success',
			),
		);
		yield 'the run failed' => array(
			array( 'workflow_run' => array( 'conclusion' => 'failure' ) ),
			array(
				'repository'    => 'LibreSign/site',
				'workflow_name' => 'pages build and deployment',
				'head_branch'   => 'gh-pages',
				'conclusion'    => 'failure',
			),
		);
		yield 'another branch' => array(
			array( 'workflow_run' => array( 'head_branch' => 'main' ) ),
			array(
				'repository'    => 'LibreSign/site',
				'workflow_name' => 'pages build and deployment',
				'head_branch'   => 'main',
				'conclusion'    => 'success',
			),
		);
		yield 'another workflow' => array(
			array( 'workflow_run' => array( 'name' => 'tests' ) ),
			array(
				'repository'    => 'LibreSign/site',
				'workflow_name' => 'tests',
				'head_branch'   => 'gh-pages',
				'conclusion'    => 'success',
			),
		);
	}

	public function test_a_decision_that_is_not_a_deploy_has_no_workflow_run() {
		$decision = self::gate()->decide( self::signed_delivery( 'push', '{"ref":"refs/heads/main"}' ) );

		$this->expectException( LogicException::class );

		$decision->workflow_run();
	}

	public function test_a_production_deploy_is_handed_over_with_the_run() {
		$decision = self::gate()->decide( self::signed_delivery( 'workflow_run', self::production_payload() ) );

		$this->assertTrue( $decision->is_deploy() );
		$this->assertSame( '0f1e2d3', $decision->workflow_run()->head_sha() );
	}
}
