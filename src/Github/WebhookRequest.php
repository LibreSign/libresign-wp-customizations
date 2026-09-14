<?php
/**
 * Delivery received on the webhook endpoint.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * The headers and the body of a delivery, with nothing read from the request.
 */
final class WebhookRequest {

	/**
	 * User-Agent header.
	 *
	 * @var string
	 */
	private $user_agent;

	/**
	 * X-GitHub-Event header.
	 *
	 * @var string
	 */
	private $event;

	/**
	 * X-Hub-Signature-256 header.
	 *
	 * @var string
	 */
	private $signature;

	/**
	 * X-GitHub-Delivery header.
	 *
	 * @var string
	 */
	private $delivery_id;

	/**
	 * Raw request body.
	 *
	 * @var string
	 */
	private $body;

	/**
	 * @param string $user_agent  User-Agent header.
	 * @param string $event       X-GitHub-Event header.
	 * @param string $signature   X-Hub-Signature-256 header.
	 * @param string $delivery_id X-GitHub-Delivery header.
	 * @param string $body        Raw request body.
	 */
	public function __construct( $user_agent, $event, $signature, $delivery_id, $body ) {
		$this->user_agent  = (string) $user_agent;
		$this->event       = (string) $event;
		$this->signature   = (string) $signature;
		$this->delivery_id = (string) $delivery_id;
		$this->body        = (string) $body;
	}

	/**
	 * Whether the client identifies itself as GitHub Hookshot.
	 *
	 * @return bool
	 */
	public function is_from_github() {
		return 0 === strpos( trim( $this->user_agent ), 'GitHub-Hookshot/' );
	}

	/**
	 * Whether the body carries the signature of the secret.
	 *
	 * @param string $secret Shared secret.
	 * @return bool
	 */
	public function has_valid_signature( $secret ) {
		return WebhookSignature::matches( $this->body, $this->signature, $secret );
	}

	/**
	 * Event name, normalized.
	 *
	 * @return string
	 */
	public function event() {
		return strtolower( trim( $this->event ) );
	}

	/**
	 * Delivery identifier, as GitHub sent it.
	 *
	 * @return string
	 */
	public function delivery_id() {
		return $this->delivery_id;
	}

	/**
	 * Parsed body, or null when it is not a JSON object.
	 *
	 * @return array<string, mixed>|null
	 */
	public function payload() {
		$payload = json_decode( $this->body, true );

		return is_array( $payload ) ? $payload : null;
	}
}
