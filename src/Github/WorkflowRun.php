<?php
/**
 * Workflow run described by a webhook payload.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * Reads the fields the site deploy cares about out of a workflow_run payload.
 */
final class WorkflowRun {

	/**
	 * Parsed payload.
	 *
	 * @var array<string, mixed>
	 */
	private $payload;

	/**
	 * @param array<string, mixed> $payload Parsed payload.
	 */
	private function __construct( array $payload ) {
		$this->payload = $payload;
	}

	/**
	 * @param array<string, mixed> $payload Parsed payload.
	 * @return self
	 */
	public static function from_payload( array $payload ) {
		return new self( $payload );
	}

	/**
	 * Repository the run belongs to, as owner/name.
	 *
	 * @return string
	 */
	public function repository() {
		return $this->text( array( 'repository', 'full_name' ) );
	}

	/**
	 * What happened to the run: requested, in_progress or completed.
	 *
	 * @return string
	 */
	public function action() {
		return $this->text( array( 'action' ) );
	}

	/**
	 * How the run ended: success, failure, cancelled and so on.
	 *
	 * @return string
	 */
	public function conclusion() {
		return $this->text( array( 'workflow_run', 'conclusion' ) );
	}

	/**
	 * Branch the run was started from.
	 *
	 * @return string
	 */
	public function head_branch() {
		return $this->text( array( 'workflow_run', 'head_branch' ) );
	}

	/**
	 * Commit the run was started from.
	 *
	 * @return string
	 */
	public function head_sha() {
		return $this->text( array( 'workflow_run', 'head_sha' ) );
	}

	/**
	 * Address of the run on GitHub.
	 *
	 * @return string
	 */
	public function html_url() {
		return $this->text( array( 'workflow_run', 'html_url' ) );
	}

	/**
	 * When GitHub last touched the run.
	 *
	 * @return string
	 */
	public function updated_at() {
		return $this->text( array( 'workflow_run', 'updated_at' ) );
	}

	/**
	 * Name of the workflow, preferring the name the run itself carries.
	 *
	 * @return string
	 */
	public function workflow_name() {
		$run_name = $this->text( array( 'workflow_run', 'name' ) );

		return '' === $run_name ? $this->text( array( 'workflow', 'name' ) ) : $run_name;
	}

	/**
	 * Value at a path of the payload, as a trimmed string.
	 *
	 * @param string[] $path Keys to walk.
	 * @return string
	 */
	private function text( array $path ) {
		$value = $this->payload;

		foreach ( $path as $key ) {
			if ( ! is_array( $value ) || ! isset( $value[ $key ] ) ) {
				return '';
			}

			$value = $value[ $key ];
		}

		return is_scalar( $value ) ? trim( (string) $value ) : '';
	}
}
