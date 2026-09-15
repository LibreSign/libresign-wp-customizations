<?php
/**
 * Inspection of a webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * Everything the endpoint refuses is refused here, so the endpoint itself only
 * turns a decision into a response.
 */
final class WebhookGate {

	private string $secret;
	private SiteDeploy $site_deploy;

	public function __construct( string $secret, SiteDeploy $site_deploy ) {
		$this->secret      = $secret;
		$this->site_deploy = $site_deploy;
	}

	public function decide( WebhookRequest $request ): WebhookDecision {
		if ( '' === trim( $this->secret ) ) {
			return WebhookDecision::reject(
				'libresign_github_webhook_secret_missing',
				__( 'The GitHub webhook secret is not configured.', 'libresign-wp-customizations' ),
				503
			);
		}

		if ( ! $request->is_from_github() ) {
			return WebhookDecision::reject(
				'libresign_github_webhook_invalid_agent',
				__( 'The webhook request does not look like a GitHub delivery.', 'libresign-wp-customizations' ),
				403
			);
		}

		if ( ! $request->has_valid_signature( $this->secret ) ) {
			return WebhookDecision::reject(
				'libresign_github_webhook_invalid_signature',
				__( 'Invalid GitHub webhook signature.', 'libresign-wp-customizations' ),
				403
			);
		}

		if ( 'ping' === $request->event() ) {
			return WebhookDecision::pong();
		}

		if ( 'workflow_run' !== $request->event() ) {
			return WebhookDecision::ignore( 'unsupported_event', array( 'event' => $request->event() ) );
		}

		$payload = $request->payload();

		if ( null === $payload ) {
			return WebhookDecision::reject(
				'libresign_github_webhook_invalid_payload',
				__( 'The GitHub webhook payload must be valid JSON.', 'libresign-wp-customizations' ),
				400
			);
		}

		$workflow_run = WorkflowRun::from_payload( $payload );

		if ( ! $this->site_deploy->is_production_run( $workflow_run ) ) {
			return WebhookDecision::ignore(
				'not_production_deploy',
				array(
					'repository'    => $workflow_run->repository(),
					'workflow_name' => $workflow_run->workflow_name(),
					'head_branch'   => $workflow_run->head_branch(),
					'conclusion'    => $workflow_run->conclusion(),
				)
			);
		}

		return WebhookDecision::deploy( $workflow_run );
	}
}
