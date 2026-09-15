<?php
/**
 * Deploy of the static site requested from the editor.
 *
 * @package LibreSign_WP_Customizations
 */

namespace LibreSign\WPCustomizations\Github;

defined( 'ABSPATH' ) || exit;

final class DeployDispatch {

	/**
	 * Only an entry of the blog deploys the site, whether it is being published
	 * or leaving the publish status.
	 */
	public static function triggers_deploy( string $new_status, string $old_status, string $post_type ): bool {
		return 'post' === $post_type && ( 'publish' === $new_status || 'publish' === $old_status );
	}

	public static function success_message( string $repository ): string {
		return 'Ação de deploy enviada com sucesso. Acompanhe <a href="https://github.com/' . $repository . '/actions" target="_blank">aqui</a>';
	}

	public static function failure_message( int $code, string $api_message ): string {
		return "Erro ao acionar deploy.<br />Código: <strong>{$code}</strong>.<br />Message: <strong>{$api_message}</strong>";
	}
}
