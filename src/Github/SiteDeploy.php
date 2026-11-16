<?php
/**
 * The workflow run that publishes the static site.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

final class SiteDeploy {

	private string $repository;
	private string $branch_name;
	private string $workflow_name;

	public function __construct( string $repository, string $branch_name, string $workflow_name ) {
		$this->repository    = $repository;
		$this->branch_name   = $branch_name;
		$this->workflow_name = $workflow_name;
	}

	public function is_production_run( WorkflowRun $workflow_run ): bool {
		return $this->repository === $workflow_run->repository()
			&& 'completed' === $workflow_run->action()
			&& 'success' === $workflow_run->conclusion()
			&& $this->branch_name === $workflow_run->head_branch()
			&& $this->workflow_name === $workflow_run->workflow_name();
	}
}
