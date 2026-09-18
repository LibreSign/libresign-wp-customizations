<?php
/**
 * GitHub webhook receiver for production site deploy synchronization.
 *
 * @package LibreSign_WP_Customizations
 */

use LibreSign\WPCustomizations\Github\SiteDeploy;
use LibreSign\WPCustomizations\Github\WebhookGate;
use LibreSign\WPCustomizations\Github\WebhookRequest;

defined( 'ABSPATH' ) || exit;

const LIBRESIGN_GITHUB_SITE_WEBHOOK_NAMESPACE = 'libresign/v1';
const LIBRESIGN_GITHUB_SITE_WEBHOOK_ROUTE     = '/site-deploy-webhook';

/**
 * Register the GitHub site deploy webhook endpoint.
 *
 * @return void
 */
function libresign_register_github_site_webhook_route() {
	register_rest_route(
		LIBRESIGN_GITHUB_SITE_WEBHOOK_NAMESPACE,
		LIBRESIGN_GITHUB_SITE_WEBHOOK_ROUTE,
		array(
			'methods'             => 'POST',
			'callback'            => 'libresign_receive_github_site_deploy_webhook',
			'permission_callback' => '__return_true',
		)
	);
}
add_action( 'rest_api_init', 'libresign_register_github_site_webhook_route' );

/**
 * Return the full webhook endpoint URL.
 *
 * @return string
 */
function libresign_github_site_webhook_endpoint_url() {
	return rest_url( ltrim( LIBRESIGN_GITHUB_SITE_WEBHOOK_NAMESPACE . LIBRESIGN_GITHUB_SITE_WEBHOOK_ROUTE, '/' ) );
}

/**
 * Resolve the configured GitHub webhook secret.
 *
 * @return string
 */
function libresign_github_webhook_secret() {
	return libresign_plugin_secret()->decrypt( get_option( 'libresign_github_webhook_secret', '' ) );
}

/**
 * Resolve the configured static site origin.
 *
 * @return string
 */
function libresign_site_origin() {
	$origin = (string) get_option( 'libresign_site_origin', 'https://libresign.coop' );

	return libresign_site_fragment_normalize_site_origin( $origin );
}

/**
 * Resolve the expected workflow name.
 *
 * @return string
 */
function libresign_site_deploy_workflow_name() {
	$name = trim( (string) get_option( 'libresign_site_deploy_workflow_name', 'pages build and deployment' ) );

	return '' === $name ? 'pages build and deployment' : $name;
}

/**
 * Resolve the expected site repository name.
 *
 * @return string
 */
function libresign_site_deploy_repository_name() {
	$name = trim( (string) get_option( 'libresign_github_deploy_organization_repository', 'LibreSign/site' ) );

	return '' === $name ? 'LibreSign/site' : $name;
}

/**
 * Resolve the expected production branch.
 *
 * @return string
 */
function libresign_site_deploy_branch_name() {
	$name = trim( (string) get_option( 'libresign_site_deploy_branch_name', 'gh-pages' ) );

	return '' === $name ? 'gh-pages' : $name;
}

/**
 * @return SiteDeploy
 */
function libresign_site_deploy() {
	return new SiteDeploy(
		libresign_site_deploy_repository_name(),
		libresign_site_deploy_branch_name(),
		libresign_site_deploy_workflow_name()
	);
}

/**
 * Build a standardized ignored response.
 *
 * @param array<string, mixed> $data   Response data.
 * @param int                  $status HTTP status.
 * @return WP_REST_Response
 */
function libresign_github_site_webhook_ignored_response( $data = array(), $status = 202 ) {
	$response = rest_ensure_response( array_merge( array( 'status' => 'ignored' ), $data ) );
	$response->set_status( $status );

	return $response;
}

/**
 * Mark a webhook delivery as processed, returning false when duplicated.
 *
 * @param string $delivery_id Delivery GUID.
 * @return bool
 */
function libresign_mark_github_delivery_once( $delivery_id ) {
	$delivery_id = trim( (string) $delivery_id );
	if ( '' === $delivery_id ) {
		return true;
	}

	$key = 'libresign_github_delivery_' . md5( $delivery_id );
	if ( get_transient( $key ) ) {
		return false;
	}

	set_transient( $key, 1, DAY_IN_SECONDS );

	return true;
}

/**
 * Record the last fragment synchronization result.
 *
 * @param string               $status  Status label.
 * @param array<string, mixed> $payload Details.
 * @return void
 */
function libresign_record_site_fragment_sync_result( $status, $payload ) {
	update_option(
		'libresign_site_fragment_last_sync',
		array(
			'status'      => $status,
			'updated_at'  => current_time( 'mysql' ),
			'details'     => $payload,
		),
		false
	);
}

/**
 * Receive the GitHub webhook and synchronize fragments after production deploys.
 *
 * @param WP_REST_Request $request REST request.
 * @return WP_REST_Response|WP_Error
 */
function libresign_receive_github_site_deploy_webhook( $request ) {
	$webhook_gate = new WebhookGate( libresign_github_webhook_secret(), libresign_site_deploy() );

	$decision = $webhook_gate->decide(
		new WebhookRequest(
			(string) $request->get_header( 'user-agent' ),
			(string) $request->get_header( 'x-github-event' ),
			(string) $request->get_header( 'x-hub-signature-256' ),
			(string) $request->get_header( 'x-github-delivery' ),
			(string) $request->get_body()
		)
	);

	if ( $decision->is_rejected() ) {
		return new WP_Error(
			$decision->code(),
			$decision->message(),
			array( 'status' => $decision->status() )
		);
	}

	if ( $decision->is_pong() ) {
		return rest_ensure_response(
			array(
				'status'   => 'pong',
				'endpoint' => libresign_github_site_webhook_endpoint_url(),
			)
		);
	}

	if ( $decision->is_ignored() ) {
		return libresign_github_site_webhook_ignored_response( $decision->data() );
	}

	$workflow_run = $decision->workflow_run();
	$delivery_id  = (string) $request->get_header( 'x-github-delivery' );

	if ( ! libresign_mark_github_delivery_once( $delivery_id ) ) {
		return libresign_github_site_webhook_ignored_response(
			array(
				'reason'      => 'duplicate_delivery',
				'delivery_id' => $delivery_id,
			)
		);
	}

	$sync_result = libresign_sync_site_fragments_from_origin(
		libresign_site_origin(),
		array( 'header', 'footer' ),
		array(
			'generated_at' => '' === $workflow_run->updated_at() ? current_time( 'mysql', true ) : $workflow_run->updated_at(),
			'source_sha'   => $workflow_run->head_sha(),
			'source_url'   => $workflow_run->html_url(),
		)
	);

	if ( is_wp_error( $sync_result ) ) {
		libresign_record_site_fragment_sync_result(
			'error',
			array(
				'message' => $sync_result->get_error_message(),
				'code'    => $sync_result->get_error_code(),
			)
		);

		return $sync_result;
	}

	libresign_record_site_fragment_sync_result(
		'synced',
		array(
			'delivery_id' => $delivery_id,
			'repository'  => $workflow_run->repository(),
			'workflow'    => $workflow_run->workflow_name(),
			'head_branch' => $workflow_run->head_branch(),
			'source_sha'  => $workflow_run->head_sha(),
			'source_url'  => $workflow_run->html_url(),
			'synced'      => $sync_result['synced'],
		)
	);

	return rest_ensure_response(
		array(
			'status'      => 'synced',
			'delivery_id' => $delivery_id,
			'repository'  => $workflow_run->repository(),
			'workflow'    => $workflow_run->workflow_name(),
			'origin'      => $sync_result['origin'],
			'synced'      => $sync_result['synced'],
		)
	);
}
