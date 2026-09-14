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
	private $branch;

	/**
	 * Name of the workflow publishing the site.
	 *
	 * @var string
	 */
	private $workflow;

	/**
	 * @param string $repository Repository publishing the site.
	 * @param string $branch     Branch the site is published from.
	 * @param string $workflow   Name of the workflow publishing the site.
	 */
	public function __construct( $repository, $branch, $workflow ) {
		$this->repository = (string) $repository;
		$this->branch     = (string) $branch;
		$this->workflow   = (string) $workflow;
	}

	/**
	 * Whether the run is the one that just put the site live.
	 *
	 * @param WorkflowRun $run Run reported by GitHub.
	 * @return bool
	 */
	public function is_production_run( WorkflowRun $run ) {
		return $this->repository === $run->repository()
			&& 'completed' === $run->action()
			&& 'success' === $run->conclusion()
			&& $this->branch === $run->head_branch()
			&& $this->workflow === $run->workflow_name();
	}
}
