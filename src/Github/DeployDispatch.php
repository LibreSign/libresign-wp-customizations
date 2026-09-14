<?php
/**
 * Deploy of the static site requested from the editor.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

/**
 * When to ask GitHub for a deploy, and what to tell the editor afterwards.
 */
final class DeployDispatch {

	/**
	 * Whether a post status transition asks for a deploy.
	 *
	 * Only an entry of the blog deploys the site, whether it is being published
	 * or leaving the publish status.
	 *
	 * @param string $new_status Status the post moved to.
	 * @param string $old_status Status the post came from.
	 * @param string $post_type  Post type.
	 * @return bool
	 */
	public static function triggers_deploy( $new_status, $old_status, $post_type ) {
		return 'post' === $post_type && ( 'publish' === $new_status || 'publish' === $old_status );
	}

	/**
	 * Notice shown when GitHub accepted the deploy.
	 *
	 * @param string $repository Repository the deploy was requested from.
	 * @return string
	 */
	public static function success_message( $repository ) {
		return 'Ação de deploy enviada com sucesso. Acompanhe <a href="https://github.com/' . $repository . '/actions" target="_blank">aqui</a>';
	}

	/**
	 * Notice shown when GitHub refused the deploy.
	 *
	 * @param int    $code        HTTP status code returned by GitHub.
	 * @param string $api_message Message carried by the response body.
	 * @return string
	 */
	public static function failure_message( $code, $api_message ) {
		return "Erro ao acionar deploy.<br />Código: <strong>{$code}</strong>.<br />Message: <strong>{$api_message}</strong>";
	}
}
