<?php
/**
 * Characterization tests for the GitHub site deploy webhook endpoint.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Tests\Integration\Includes;

use LibreSign\WPCustomizations\Tests\Support\FakeHttp;
use LibreSign\WPCustomizations\Tests\Support\RegistersPluginSettings;
use WP_Error;
use WP_REST_Request;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Exercises the endpoint through the real REST server, with the outgoing
 * fragment requests short-circuited by the pre_http_request filter.
 */
final class GithubSiteWebhookTest extends WP_UnitTestCase {

	use RegistersPluginSettings;

	private const ROUTE  = '/libresign/v1/site-deploy-webhook';
	private const SECRET = 'webhook-secret';

	/**
	 * The static site origin, answered locally.
	 *
	 * @var FakeHttp
	 */
	private $origin;

	public function set_up() {
		parent::set_up();

		$this->origin = new FakeHttp();

		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server();
		do_action( 'rest_api_init', $wp_rest_server );

		update_option( 'libresign_github_webhook_secret', self::SECRET );
		update_option( 'libresign_github_deploy_organization_repository', 'LibreSign/site' );
		update_option( 'libresign_site_deploy_workflow_name', 'pages build and deployment' );
		update_option( 'libresign_site_deploy_branch_name', 'gh-pages' );
		update_option( 'libresign_site_origin', 'https://libresign.coop' );
	}

	public function tear_down() {
		global $wp_rest_server;
		$wp_rest_server = null;

		parent::tear_down();
	}

	/**
	 * Payload of a production deploy run.
	 *
	 * @param array<string, mixed> $overrides Values replacing the defaults.
	 * @return array<string, mixed>
	 */
	private static function production_payload( $overrides = array() ) {
		return array_replace_recursive(
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
			),
			$overrides
		);
	}

	/**
	 * Build a request signed with the configured secret.
	 *
	 * @param string $event       X-GitHub-Event header.
	 * @param string $body        Raw request body.
	 * @param string $delivery_id X-GitHub-Delivery header.
	 * @return WP_REST_Request
	 */
	private function signed_request( $event, $body, $delivery_id = 'delivery-1' ) {
		$request = new WP_REST_Request( 'POST', self::ROUTE );
		$request->set_header( 'user-agent', 'GitHub-Hookshot/044aadd' );
		$request->set_header( 'x-github-event', $event );
		$request->set_header( 'x-github-delivery', $delivery_id );
		$request->set_header( 'content-type', 'application/json' );
		$request->set_header( 'x-hub-signature-256', 'sha256=' . hash_hmac( 'sha256', $body, self::SECRET ) );
		$request->set_body( $body );

		return $request;
	}

	public function test_the_route_is_registered() {
		$this->assertArrayHasKey( self::ROUTE, rest_get_server()->get_routes() );
	}

	public function test_the_endpoint_url_points_at_the_route() {
		$this->assertSame( rest_url( 'libresign/v1/site-deploy-webhook' ), libresign_github_site_webhook_endpoint_url() );
	}

	public function test_an_unconfigured_secret_makes_the_endpoint_unavailable() {
		delete_option( 'libresign_github_webhook_secret' );

		$response = rest_get_server()->dispatch( $this->signed_request( 'ping', '{}' ) );

		$this->assertSame( 503, $response->get_status() );
		$this->assertSame( 'libresign_github_webhook_secret_missing', $response->get_data()['code'] );
	}

	public function test_a_request_from_another_client_is_rejected() {
		$request = $this->signed_request( 'ping', '{}' );
		$request->set_header( 'user-agent', 'curl/8.7.1' );

		$response = rest_get_server()->dispatch( $request );

		$this->assertSame( 403, $response->get_status() );
		$this->assertSame( 'libresign_github_webhook_invalid_agent', $response->get_data()['code'] );
	}

	public function test_a_wrongly_signed_request_is_rejected() {
		$request = $this->signed_request( 'ping', '{}' );
		$request->set_header( 'x-hub-signature-256', 'sha256=' . hash_hmac( 'sha256', '{}', 'another-secret' ) );

		$response = rest_get_server()->dispatch( $request );

		$this->assertSame( 403, $response->get_status() );
		$this->assertSame( 'libresign_github_webhook_invalid_signature', $response->get_data()['code'] );
	}

	public function test_a_ping_is_answered_with_the_endpoint_url() {
		$response = rest_get_server()->dispatch( $this->signed_request( 'ping', '{"zen":"Design for failure."}' ) );

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 'pong', $response->get_data()['status'] );
		$this->assertSame( libresign_github_site_webhook_endpoint_url(), $response->get_data()['endpoint'] );
	}

	public function test_another_event_is_ignored() {
		$response = rest_get_server()->dispatch( $this->signed_request( 'push', '{"ref":"refs/heads/main"}' ) );

		$this->assertSame( 202, $response->get_status() );
		$this->assertSame( 'ignored', $response->get_data()['status'] );
		$this->assertSame( 'unsupported_event', $response->get_data()['reason'] );
		$this->assertSame( 'push', $response->get_data()['event'] );
	}

	public function test_a_json_body_that_does_not_parse_never_reaches_the_callback() {
		$response = rest_get_server()->dispatch( $this->signed_request( 'workflow_run', 'not json' ) );

		$this->assertSame( 400, $response->get_status() );
		$this->assertSame( 'rest_invalid_json', $response->get_data()['code'] );
	}

	public function test_a_body_that_is_not_json_is_rejected_by_the_callback() {
		$request = $this->signed_request( 'workflow_run', 'not json' );
		$request->set_header( 'content-type', 'text/plain' );

		$response = rest_get_server()->dispatch( $request );

		$this->assertSame( 400, $response->get_status() );
		$this->assertSame( 'libresign_github_webhook_invalid_payload', $response->get_data()['code'] );
	}

	/**
	 * @dataProvider provide_non_production_payloads
	 *
	 * @param array<string, mixed> $overrides Values replacing the production defaults.
	 */
	public function test_a_run_that_is_not_the_production_deploy_is_ignored( $overrides ) {
		$body = wp_json_encode( self::production_payload( $overrides ) );

		$response = rest_get_server()->dispatch( $this->signed_request( 'workflow_run', $body ) );

		$this->assertSame( 202, $response->get_status() );
		$this->assertSame( 'not_production_deploy', $response->get_data()['reason'] );
		$this->assertSame( array(), $this->origin->urls() );
	}

	/**
	 * @return iterable<string, array{0: array<string, mixed>}>
	 */
	public static function provide_non_production_payloads() {
		yield 'another repository'  => array( array( 'repository' => array( 'full_name' => 'LibreSign/libresign' ) ) );
		yield 'the run is starting' => array( array( 'action' => 'requested' ) );
		yield 'the run failed'      => array( array( 'workflow_run' => array( 'conclusion' => 'failure' ) ) );
		yield 'another branch'      => array( array( 'workflow_run' => array( 'head_branch' => 'main' ) ) );
		yield 'another workflow'    => array( array( 'workflow_run' => array( 'name' => 'tests' ) ) );
	}

	public function test_a_production_deploy_synchronizes_the_fragments() {
		$this->origin->answer_with( FakeHttp::response( 200, '<header>site</header>' ) );

		$body     = wp_json_encode( self::production_payload() );
		$response = rest_get_server()->dispatch( $this->signed_request( 'workflow_run', $body ) );
		$data     = $response->get_data();

		$this->assertSame( 200, $response->get_status() );
		$this->assertSame( 'synced', $data['status'] );
		$this->assertSame( array( 'header', 'footer' ), $data['synced'] );
		$this->assertSame( 'https://libresign.coop', $data['origin'] );
		$this->assertSame( 'delivery-1', $data['delivery_id'] );
		$this->assertSame(
			array(
				'https://libresign.coop/fragments/header/',
				'https://libresign.coop/fragments/footer/',
			),
			$this->origin->urls()
		);
		$this->assertSame( '<header>site</header>', libresign_get_site_fragment_html( 'header' ) );
	}

	public function test_a_production_deploy_records_the_last_synchronization() {
		$this->origin->answer_with( FakeHttp::response( 200, '<header>site</header>' ) );

		$body = wp_json_encode( self::production_payload() );
		rest_get_server()->dispatch( $this->signed_request( 'workflow_run', $body ) );

		$last_sync = get_option( 'libresign_site_fragment_last_sync' );

		$this->assertSame( 'synced', $last_sync['status'] );
		$this->assertSame( 'LibreSign/site', $last_sync['details']['repository'] );
		$this->assertSame( '0f1e2d3', $last_sync['details']['source_sha'] );
		$this->assertSame( array( 'header', 'footer' ), $last_sync['details']['synced'] );
	}

	public function test_the_same_delivery_is_only_processed_once() {
		$this->origin->answer_with( FakeHttp::response( 200, '<header>site</header>' ) );

		$body = wp_json_encode( self::production_payload() );
		rest_get_server()->dispatch( $this->signed_request( 'workflow_run', $body, 'delivery-42' ) );
		$this->origin->forget();

		$response = rest_get_server()->dispatch( $this->signed_request( 'workflow_run', $body, 'delivery-42' ) );

		$this->assertSame( 202, $response->get_status() );
		$this->assertSame( 'duplicate_delivery', $response->get_data()['reason'] );
		$this->assertSame( array(), $this->origin->urls() );
	}

	public function test_a_failing_origin_is_reported_and_recorded() {
		$this->origin->answer_with( new WP_Error( 'http_request_failed', 'Connection refused' ) );

		$body     = wp_json_encode( self::production_payload() );
		$response = rest_get_server()->dispatch( $this->signed_request( 'workflow_run', $body ) );

		$this->assertTrue( $response->is_error() );
		$this->assertSame( 'http_request_failed', $response->get_data()['code'] );

		$last_sync = get_option( 'libresign_site_fragment_last_sync' );

		$this->assertSame( 'error', $last_sync['status'] );
		$this->assertSame( 'http_request_failed', $last_sync['details']['code'] );
	}

	public function test_the_delivery_guard_lets_the_first_delivery_through() {
		$this->assertTrue( libresign_mark_github_delivery_once( 'abc' ) );
		$this->assertFalse( libresign_mark_github_delivery_once( 'abc' ) );
		$this->assertTrue( libresign_mark_github_delivery_once( 'def' ) );
	}

	public function test_a_delivery_without_an_identifier_is_never_blocked() {
		$this->assertTrue( libresign_mark_github_delivery_once( '' ) );
		$this->assertTrue( libresign_mark_github_delivery_once( '   ' ) );
	}

	/**
	 * @dataProvider provide_stored_options
	 *
	 * @param string   $option   Option name.
	 * @param mixed    $stored   Value stored in the database.
	 * @param callable $resolver Function resolving the option.
	 * @param string   $expected Expected resolved value.
	 */
	public function test_option_resolvers_fall_back_to_the_production_defaults( $option, $stored, $resolver, $expected ) {
		if ( null === $stored ) {
			delete_option( $option );
		} else {
			update_option( $option, $stored );
		}

		$this->assertSame( $expected, call_user_func( $resolver ) );
	}

	/**
	 * @return iterable<string, array{0: string, 1: mixed, 2: callable, 3: string}>
	 */
	public static function provide_stored_options() {
		yield 'the workflow name is stored' => array(
			'libresign_site_deploy_workflow_name',
			'deploy',
			'libresign_site_deploy_workflow_name',
			'deploy',
		);
		yield 'the workflow name is trimmed' => array(
			'libresign_site_deploy_workflow_name',
			'  deploy  ',
			'libresign_site_deploy_workflow_name',
			'deploy',
		);
		yield 'no workflow name falls back' => array(
			'libresign_site_deploy_workflow_name',
			null,
			'libresign_site_deploy_workflow_name',
			'pages build and deployment',
		);
		yield 'a blank workflow name falls back' => array(
			'libresign_site_deploy_workflow_name',
			'   ',
			'libresign_site_deploy_workflow_name',
			'pages build and deployment',
		);
		yield 'no branch falls back' => array(
			'libresign_site_deploy_branch_name',
			null,
			'libresign_site_deploy_branch_name',
			'gh-pages',
		);
		yield 'no repository falls back' => array(
			'libresign_github_deploy_organization_repository',
			null,
			'libresign_site_deploy_repository_name',
			'LibreSign/site',
		);
		yield 'no origin falls back' => array(
			'libresign_site_origin',
			null,
			'libresign_site_origin',
			'https://libresign.coop',
		);
		yield 'the origin loses its trailing slash' => array(
			'libresign_site_origin',
			'https://staging.libresign.coop/',
			'libresign_site_origin',
			'https://staging.libresign.coop',
		);
	}

	public function test_a_secret_stored_in_plain_text_is_used_as_is() {
		update_option( 'libresign_github_webhook_secret', 'plain-secret' );

		$this->assertSame( 'plain-secret', libresign_github_webhook_secret() );
	}

	public function test_a_secret_saved_over_an_existing_one_is_stored_encrypted() {
		$this->register_plugin_settings();

		update_option( 'libresign_github_webhook_secret', 'saved-from-the-form' );

		$this->assertNotSame( 'saved-from-the-form', get_option( 'libresign_github_webhook_secret' ) );
		$this->assertSame( 'saved-from-the-form', libresign_github_webhook_secret() );
	}

	/**
	 * Current behaviour, and a bug: update_option() sanitizes the value and,
	 * when the option does not exist yet, hands it to add_option(), which
	 * sanitizes it again. A secret saved on a site that never had one is
	 * therefore encrypted twice, and every delivery GitHub signs with it is
	 * answered with an invalid signature until the secret is saved again.
	 */
	public function test_a_secret_saved_for_the_first_time_is_encrypted_twice() {
		delete_option( 'libresign_github_webhook_secret' );
		$this->register_plugin_settings();

		update_option( 'libresign_github_webhook_secret', 'saved-from-the-form' );

		$this->assertNotSame( 'saved-from-the-form', libresign_github_webhook_secret() );
	}

	public function test_saving_an_empty_secret_keeps_the_previous_one() {
		$this->register_plugin_settings();

		update_option( 'libresign_github_webhook_secret', 'saved-from-the-form' );
		update_option( 'libresign_github_webhook_secret', '' );

		$this->assertSame( 'saved-from-the-form', libresign_github_webhook_secret() );
	}
}
