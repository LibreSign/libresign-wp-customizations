<?php
/**
 * What to do with a webhook delivery.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * The outcome of inspecting a delivery, with no answer sent yet.
 */
final class WebhookDecision {

	private const REJECT = 'reject';
	private const PONG   = 'pong';
	private const IGNORE = 'ignore';
	private const DEPLOY = 'deploy';

	/**
	 * One of the constants above.
	 *
	 * @var string
	 */
	private $outcome;

	/**
	 * Error code of a rejection.
	 *
	 * @var string
	 */
	private $code = '';

	/**
	 * Error message of a rejection.
	 *
	 * @var string
	 */
	private $message = '';

	/**
	 * HTTP status of a rejection.
	 *
	 * @var int
	 */
	private $status = 0;

	/**
	 * Why the delivery was ignored, and the details worth reporting.
	 *
	 * @var array<string, mixed>
	 */
	private $data = array();

	/**
	 * Run to deploy from.
	 *
	 * @var WorkflowRun|null
	 */
	private $workflow_run;

	/**
	 * @param string $outcome One of the class constants.
	 */
	private function __construct( $outcome ) {
		$this->outcome = $outcome;
	}

	/**
	 * The delivery is not one this endpoint answers.
	 *
	 * @param string $code    Error code.
	 * @param string $message Error message.
	 * @param int    $status  HTTP status.
	 * @return self
	 */
	public static function reject( $code, $message, $status ) {
		$decision          = new self( self::REJECT );
		$decision->code    = (string) $code;
		$decision->message = (string) $message;
		$decision->status  = (int) $status;

		return $decision;
	}

	/**
	 * GitHub is checking the endpoint is alive.
	 *
	 * @return self
	 */
	public static function pong() {
		return new self( self::PONG );
	}

	/**
	 * A delivery this endpoint accepts but has nothing to do about.
	 *
	 * @param string               $reason  Why it was ignored.
	 * @param array<string, mixed> $details Details worth reporting back.
	 * @return self
	 */
	public static function ignore( $reason, array $details = array() ) {
		$decision       = new self( self::IGNORE );
		$decision->data = array_merge( array( 'reason' => (string) $reason ), $details );

		return $decision;
	}

	/**
	 * The site was just published and the fragments are stale.
	 *
	 * @param WorkflowRun $run Run that published the site.
	 * @return self
	 */
	public static function deploy( WorkflowRun $run ) {
		$decision               = new self( self::DEPLOY );
		$decision->workflow_run = $run;

		return $decision;
	}

	/**
	 * @return bool
	 */
	public function is_rejected() {
		return self::REJECT === $this->outcome;
	}

	/**
	 * @return bool
	 */
	public function is_pong() {
		return self::PONG === $this->outcome;
	}

	/**
	 * @return bool
	 */
	public function is_ignored() {
		return self::IGNORE === $this->outcome;
	}

	/**
	 * @return bool
	 */
	public function is_deploy() {
		return self::DEPLOY === $this->outcome;
	}

	/**
	 * @return string
	 */
	public function code() {
		return $this->code;
	}

	/**
	 * @return string
	 */
	public function message() {
		return $this->message;
	}

	/**
	 * @return int
	 */
	public function status() {
		return $this->status;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function data() {
		return $this->data;
	}

	/**
	 * @return WorkflowRun|null
	 */
	public function workflow_run() {
		return $this->workflow_run;
	}
}
