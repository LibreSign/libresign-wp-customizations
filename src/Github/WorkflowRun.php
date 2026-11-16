<?php
/**
 * Workflow run described by a webhook payload.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

final class WorkflowRun {

	/**
	 * @var array<mixed>
	 */
	private array $payload;

	/**
	 * @param array<mixed> $payload Parsed payload.
	 */
	private function __construct( array $payload ) {
		$this->payload = $payload;
	}

	/**
	 * @param array<mixed> $payload Parsed payload.
	 */
	public static function from_payload( array $payload ): self {
		return new self( $payload );
	}

	public function repository(): string {
		return $this->text( array( 'repository', 'full_name' ) );
	}

	public function action(): string {
		return $this->text( array( 'action' ) );
	}

	public function conclusion(): string {
		return $this->text( array( 'workflow_run', 'conclusion' ) );
	}

	public function head_branch(): string {
		return $this->text( array( 'workflow_run', 'head_branch' ) );
	}

	public function head_sha(): string {
		return $this->text( array( 'workflow_run', 'head_sha' ) );
	}

	public function html_url(): string {
		return $this->text( array( 'workflow_run', 'html_url' ) );
	}

	public function updated_at(): string {
		return $this->text( array( 'workflow_run', 'updated_at' ) );
	}

	public function workflow_name(): string {
		$run_name = $this->text( array( 'workflow_run', 'name' ) );

		return '' === $run_name ? $this->text( array( 'workflow', 'name' ) ) : $run_name;
	}

	/**
	 * @param string[] $field_path Keys to walk.
	 */
	private function text( array $field_path ): string {
		$field_value = $this->payload;

		foreach ( $field_path as $field_name ) {
			if ( ! is_array( $field_value ) || ! isset( $field_value[ $field_name ] ) ) {
				return '';
			}

			$field_value = $field_value[ $field_name ];
		}

		return is_scalar( $field_value ) ? trim( (string) $field_value ) : '';
	}
}
