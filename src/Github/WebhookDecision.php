<?php
/**
 * What to do with a webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

use LogicException;

defined( 'ABSPATH' ) || exit;

final class WebhookDecision {

	private const REJECT = 'reject';
	private const PONG   = 'pong';
	private const IGNORE = 'ignore';
	private const DEPLOY = 'deploy';

	private string $outcome;
	private string $error_code    = '';
	private string $error_message = '';
	private int $http_status      = 0;

	/**
	 * @var array<string, mixed>
	 */
	private array $response_data = array();

	private ?WorkflowRun $workflow_run = null;

	private function __construct( string $outcome ) {
		$this->outcome = $outcome;
	}

	public static function reject( string $error_code, string $error_message, int $http_status ): self {
		$decision                = new self( self::REJECT );
		$decision->error_code    = $error_code;
		$decision->error_message = $error_message;
		$decision->http_status   = $http_status;

		return $decision;
	}

	public static function pong(): self {
		return new self( self::PONG );
	}

	/**
	 * @param array<string, mixed> $details Details worth reporting back.
	 */
	public static function ignore( string $ignored_reason, array $details = array() ): self {
		$decision                = new self( self::IGNORE );
		$decision->response_data = array_merge( array( 'reason' => $ignored_reason ), $details );

		return $decision;
	}

	public static function deploy( WorkflowRun $workflow_run ): self {
		$decision               = new self( self::DEPLOY );
		$decision->workflow_run = $workflow_run;

		return $decision;
	}

	public function is_rejected(): bool {
		return self::REJECT === $this->outcome;
	}

	public function is_pong(): bool {
		return self::PONG === $this->outcome;
	}

	public function is_ignored(): bool {
		return self::IGNORE === $this->outcome;
	}

	public function is_deploy(): bool {
		return self::DEPLOY === $this->outcome;
	}

	public function code(): string {
		return $this->error_code;
	}

	public function message(): string {
		return $this->error_message;
	}

	public function status(): int {
		return $this->http_status;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function data(): array {
		return $this->response_data;
	}

	/**
	 * @throws LogicException When the decision is not a deploy.
	 */
	public function workflow_run(): WorkflowRun {
		if ( null === $this->workflow_run ) {
			throw new LogicException( 'Only a deploy decision carries a workflow run.' );
		}

		return $this->workflow_run;
	}
}
