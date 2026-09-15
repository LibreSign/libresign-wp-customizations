<?php
/**
 * Delivery received on the webhook endpoint.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

final class WebhookRequest {

	private string $user_agent;
	private string $event;
	private string $signature;
	private string $delivery_id;
	private string $body;

	public function __construct(
		string $user_agent,
		string $event,
		string $signature,
		string $delivery_id,
		string $body
	) {
		$this->user_agent  = $user_agent;
		$this->event       = $event;
		$this->signature   = $signature;
		$this->delivery_id = $delivery_id;
		$this->body        = $body;
	}

	public function is_from_github(): bool {
		return 0 === strpos( trim( $this->user_agent ), 'GitHub-Hookshot/' );
	}

	public function has_valid_signature( string $secret ): bool {
		return WebhookSignature::matches( $this->body, $this->signature, $secret );
	}

	public function event(): string {
		return strtolower( trim( $this->event ) );
	}

	public function delivery_id(): string {
		return $this->delivery_id;
	}

	/**
	 * @return array<mixed>|null
	 */
	public function payload(): ?array {
		$payload = json_decode( $this->body, true );

		return is_array( $payload ) ? $payload : null;
	}
}
