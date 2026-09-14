<?php
/**
 * The workflow run that publishes the static site.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * Recognizes the production deploy among every run GitHub reports.
 */
final class SiteDeploy {

	/**
	 * Repository publishing the site, as owner/name.
	 *
	 * @var string
	 */
	private $repository;

	/**
	 * Branch the site is published from.
	 *
	 * @var string
	 */
	private $branch_name;

	/**
	 * Name of the workflow publishing the site.
	 *
	 * @var string
	 */
	private $workflow_name;

	/**
	 * @param string $repository Repository publishing the site.
	 * @param string $branch_name     Branch the site is published from.
	 * @param string $workflow_name   Name of the workflow publishing the site.
	 */
	public function __construct( $repository, $branch_name, $workflow_name ) {
		$this->repository    = (string) $repository;
		$this->branch_name   = (string) $branch_name;
		$this->workflow_name = (string) $workflow_name;
	}

	/**
	 * Whether the run is the one that just put the site live.
	 *
	 * @param WorkflowRun $workflow_run Run reported by GitHub.
	 * @return bool
	 */
	public function is_production_run( WorkflowRun $workflow_run ) {
		return $this->repository === $workflow_run->repository()
			&& 'completed' === $workflow_run->action()
			&& 'success' === $workflow_run->conclusion()
			&& $this->branch_name === $workflow_run->head_branch()
			&& $this->workflow_name === $workflow_run->workflow_name();
	}
}
