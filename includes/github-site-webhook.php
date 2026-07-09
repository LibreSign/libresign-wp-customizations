<?php
/**
 * GitHub webhook receiver for production site deploy synchronization.
 *
 * @package LibreSign_WP_Customizations
 */

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
 * Decrypt an encrypted plugin option value.
 *
 * @param string $value Raw stored value.
 * @return string
 */
function libresign_decrypt_plugin_secret( $value ) {
	$value = trim( (string) $value );
	if ( '' === $value ) {
		return '';
	}

	$decoded = base64_decode( $value, true );
	if ( false === $decoded ) {
		return $value;
	}

	$key = hash( 'sha256', AUTH_KEY . SECURE_AUTH_SALT );
	$iv  = substr( hash( 'sha256', NONCE_SALT ), 0, 16 );

	$decrypted = openssl_decrypt( $decoded, 'AES-256-CBC', $key, 0, $iv );

	return false === $decrypted ? $value : trim( (string) $decrypted );
}

/**
 * Resolve the configured GitHub webhook secret.
 *
 * @return string
 */
function libresign_github_webhook_secret() {
	return libresign_decrypt_plugin_secret( get_option( 'libresign_github_webhook_secret', '' ) );
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
 * Verify the GitHub webhook HMAC signature.
 *
 * @param string $body      Raw request body.
 * @param string $signature Signature header value.
 * @param string $secret    Shared secret.
 * @return bool
 */
function libresign_verify_github_webhook_signature( $body, $signature, $secret ) {
	$secret    = trim( (string) $secret );
	$signature = trim( (string) $signature );

	if ( '' === $body || '' === $secret || '' === $signature ) {
		return false;
	}

	if ( 0 === stripos( $signature, 'sha256=' ) ) {
		$signature = substr( $signature, 7 );
	}

	if ( ! ctype_xdigit( $signature ) ) {
		return false;
	}

	$expected = hash_hmac( 'sha256', $body, $secret );

	return hash_equals( $expected, strtolower( $signature ) );
}

/**
 * Check whether the webhook user agent looks like GitHub Hookshot.
 *
 * @param string $user_agent User agent header.
 * @return bool
 */
function libresign_is_github_hookshot_user_agent( $user_agent ) {
	return 0 === strpos( trim( (string) $user_agent ), 'GitHub-Hookshot/' );
}

/**
 * Extract the workflow name from the payload.
 *
 * @param array<string, mixed> $payload Parsed payload.
 * @return string
 */
function libresign_site_deploy_workflow_name_from_payload( $payload ) {
	$workflow_run_name = isset( $payload['workflow_run']['name'] ) ? trim( (string) $payload['workflow_run']['name'] ) : '';
	if ( '' !== $workflow_run_name ) {
		return $workflow_run_name;
	}

	$workflow_name = isset( $payload['workflow']['name'] ) ? trim( (string) $payload['workflow']['name'] ) : '';

	return $workflow_name;
}

/**
 * Determine whether the payload represents the production site deploy event.
 *
 * @param array<string, mixed> $payload Parsed payload.
 * @return bool
 */
function libresign_is_production_site_deploy_workflow_run( $payload ) {
	$repository = isset( $payload['repository']['full_name'] ) ? trim( (string) $payload['repository']['full_name'] ) : '';
	$action     = isset( $payload['action'] ) ? trim( (string) $payload['action'] ) : '';
	$conclusion = isset( $payload['workflow_run']['conclusion'] ) ? trim( (string) $payload['workflow_run']['conclusion'] ) : '';
	$head_branch = isset( $payload['workflow_run']['head_branch'] ) ? trim( (string) $payload['workflow_run']['head_branch'] ) : '';
	$workflow_name = libresign_site_deploy_workflow_name_from_payload( $payload );

	if ( libresign_site_deploy_repository_name() !== $repository ) {
		return false;
	}

	if ( 'completed' !== $action ) {
		return false;
	}

	if ( 'success' !== $conclusion ) {
		return false;
	}

	if ( libresign_site_deploy_branch_name() !== $head_branch ) {
		return false;
	}

	return libresign_site_deploy_workflow_name() === $workflow_name;
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
	$secret = libresign_github_webhook_secret();
	if ( '' === $secret ) {
		return new WP_Error(
			'libresign_github_webhook_secret_missing',
			__( 'The GitHub webhook secret is not configured.', 'libresign-wp-customizations' ),
			array( 'status' => 503 )
		);
	}

	$user_agent = (string) $request->get_header( 'user-agent' );
	if ( ! libresign_is_github_hookshot_user_agent( $user_agent ) ) {
		return new WP_Error(
			'libresign_github_webhook_invalid_agent',
			__( 'The webhook request does not look like a GitHub delivery.', 'libresign-wp-customizations' ),
			array( 'status' => 403 )
		);
	}

	$body      = (string) $request->get_body();
	$signature = (string) $request->get_header( 'x-hub-signature-256' );
	if ( ! libresign_verify_github_webhook_signature( $body, $signature, $secret ) ) {
		return new WP_Error(
			'libresign_github_webhook_invalid_signature',
			__( 'Invalid GitHub webhook signature.', 'libresign-wp-customizations' ),
			array( 'status' => 403 )
		);
	}

	$event = strtolower( trim( (string) $request->get_header( 'x-github-event' ) ) );
	if ( 'ping' === $event ) {
		return rest_ensure_response(
			array(
				'status'   => 'pong',
				'endpoint' => libresign_github_site_webhook_endpoint_url(),
			)
		);
	}

	if ( 'workflow_run' !== $event ) {
		return libresign_github_site_webhook_ignored_response(
			array(
				'reason' => 'unsupported_event',
				'event'  => $event,
			)
		);
	}

	$payload = json_decode( $body, true );
	if ( ! is_array( $payload ) ) {
		return new WP_Error(
			'libresign_github_webhook_invalid_payload',
			__( 'The GitHub webhook payload must be valid JSON.', 'libresign-wp-customizations' ),
			array( 'status' => 400 )
		);
	}

	if ( ! libresign_is_production_site_deploy_workflow_run( $payload ) ) {
		return libresign_github_site_webhook_ignored_response(
			array(
				'reason'         => 'not_production_deploy',
				'repository'     => isset( $payload['repository']['full_name'] ) ? (string) $payload['repository']['full_name'] : '',
				'workflow_name'  => libresign_site_deploy_workflow_name_from_payload( $payload ),
				'head_branch'    => isset( $payload['workflow_run']['head_branch'] ) ? (string) $payload['workflow_run']['head_branch'] : '',
				'conclusion'     => isset( $payload['workflow_run']['conclusion'] ) ? (string) $payload['workflow_run']['conclusion'] : '',
			)
		);
	}

	$delivery_id = (string) $request->get_header( 'x-github-delivery' );
	if ( ! libresign_mark_github_delivery_once( $delivery_id ) ) {
		return libresign_github_site_webhook_ignored_response(
			array(
				'reason'      => 'duplicate_delivery',
				'delivery_id' => $delivery_id,
			)
		);
	}

	$workflow_run = isset( $payload['workflow_run'] ) && is_array( $payload['workflow_run'] ) ? $payload['workflow_run'] : array();
	$sync_result  = libresign_sync_site_fragments_from_origin(
		libresign_site_origin(),
		array( 'header', 'footer' ),
		array(
			'generated_at' => isset( $workflow_run['updated_at'] ) ? (string) $workflow_run['updated_at'] : current_time( 'mysql', true ),
			'source_sha'   => isset( $workflow_run['head_sha'] ) ? (string) $workflow_run['head_sha'] : '',
			'source_url'   => isset( $workflow_run['html_url'] ) ? (string) $workflow_run['html_url'] : '',
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
			'repository'  => libresign_site_deploy_repository_name(),
			'workflow'    => libresign_site_deploy_workflow_name_from_payload( $payload ),
			'head_branch' => isset( $workflow_run['head_branch'] ) ? (string) $workflow_run['head_branch'] : '',
			'source_sha'  => isset( $workflow_run['head_sha'] ) ? (string) $workflow_run['head_sha'] : '',
			'source_url'  => isset( $workflow_run['html_url'] ) ? (string) $workflow_run['html_url'] : '',
			'synced'      => $sync_result['synced'],
		)
	);

	return rest_ensure_response(
		array(
			'status'      => 'synced',
			'delivery_id' => $delivery_id,
			'repository'  => libresign_site_deploy_repository_name(),
			'workflow'    => libresign_site_deploy_workflow_name_from_payload( $payload ),
			'origin'      => $sync_result['origin'],
			'synced'      => $sync_result['synced'],
		)
	);
}
