<?php
/**
 * LibreSign customizations
 *
 * @package   wp-simple-smtp
 * @author    LibreCode <contact@librecode.coop>
 * @license   GPL-2.0+
 * @link      http://github.com/libresign/libresign-wp-customizations
 * @copyright 2025 LibreCode
 *
 * @wordpress-plugin
 * Plugin Name:       LibreSign customizations
 * Plugin URI:        https://github.com/LibreSign/libresign-wp-customizations
 * Description:       Customizations at WordPress relative to website libresign.coop
 * Version:           0.0.1
 * Author:            LibreCode
 * Author URI:        https://github.com/LibreSign
 * Text Domain:       wp-simple-smtp
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * GitHub Plugin URI: https://github.com/LibreSign/libresign-wp-customizations
 */

defined( 'ABSPATH' ) || exit;


/**
 * Get gravatar
 */
add_filter( 'rest_prepare_post', function( $response, $post, $request ) {
    $author_id = $post->post_author;
    $user = get_userdata( $author_id );
    if ( $user ) {
        $email = $user->user_email;
        $gravatar_hash = md5( strtolower( trim( $email ) ) );
        $author_data = $response->get_data()['author'];
        $author_data = [
            'id' => $author_id,
            'name' => $user->display_name,
            'gravatar_hash' => $gravatar_hash,
        ];
        $data = $response->get_data();
        $data['author'] = $author_data;
        $response->set_data($data);
    }

    return $response;
}, 10, 3);

/**
 * No index and no follow if category is equals to article
 * This is to prevent that search engine robots index the posts that is internal
 */
function libresign_wp_add_noindex_meta_tag() {
    if ( is_single() && has_category('article') ) {
        echo '<meta name="robots" content="noindex, nofollow">' . PHP_EOL;
    }
}
add_action('wp_head', 'libresign_wp_add_noindex_meta_tag');

/**
 * Deploy the site after change the status of post
 */
function libresign_trigger_github_action_on_publish($new_status, $old_status, $post) {
    if ($new_status === 'publish' || $old_status === 'publish' && $post->post_type === 'post') {
        $encripted = get_option('libresign_github_deploy_token');
        $key = hash('sha256', AUTH_KEY . SECURE_AUTH_SALT);
        $iv = substr(hash('sha256', NONCE_SALT), 0, 16);
        $deploy_token = openssl_decrypt(base64_decode($encripted), 'AES-256-CBC', $key, 0, $iv);
        $organizationRepository = get_option('libresign_github_deploy_organization_repository');
        $response = wp_remote_post('https://api.github.com/repos/' . $organizationRepository . '/dispatches', [
            'body'        => json_encode([
                'event_type' => 'deploy-site',
            ]),
            'headers'     => [
                'Authorization' => 'Bearer ' . $deploy_token,
                'Accept'        => 'application/vnd.github+json',
                'User-Agent'    => 'WordPress Hook',
            ],
            'timeout'     => 15,
        ]);

        $post_data = [
            'post_id'    => $post->ID,
            'post_title' => get_the_title($post->ID),
            'language'   => function_exists('pll_get_post_language') ? pll_get_post_language($post->ID) : 'indefinido',
        ];

        if (is_wp_error($response)) {
            $post_data = array_merge($post_data, [
                'type'    => 'error',
                'message' => $response->get_error_message(),
            ]);
        } else {
            $code = wp_remote_retrieve_response_code($response);
            if ($code === 204) {
                $post_data = array_merge($post_data, [
                    'type'    => 'success',
                    'message' => 'Ação de deploy enviada com sucesso.',
                ]);
            } else {
                $body = json_decode($response['body'], true);
                $post_data = array_merge($post_data, [
                    'type'    => 'error',
                    'message' => "Erro ao acionar deploy.<br />Código: <strong>$code</strong>.<br />Message: <strong>{$body['message']}</strong>",
                ]);
            }
        }

        $transient_key = 'libresign_github_action_status_' . get_current_user_id();
        $status_list = get_transient($transient_key);
        if (!is_array($status_list)) {
            $status_list = [];
        }
        $status_list[] = $post_data;
        set_transient($transient_key, $status_list, 60);
    }
}
add_action('transition_post_status', 'libresign_trigger_github_action_on_publish', 10, 3);

/**
 * Display the status after edit
 */
function libresign_show_github_action_status_notice() {
    $user_id = get_current_user_id();
    $transient_key = 'libresign_github_action_status_' . $user_id;
    $status_list = get_transient($transient_key);
    if (!is_array($status_list)) {
        return;
    }
    delete_transient($transient_key);
    foreach ($status_list as $status) {
        $class = ($status['type'] === 'success') ? 'notice-success' : 'notice-error';
        $post_info = sprintf(
            <<<MESSAGE
            {$status['message']}<br />
            Post: <strong>%s</strong><br />
            ID: %d<br />
            Idioma: <strong>%s</strong>
            MESSAGE,
            esc_html($status['post_title']),
            intval($status['post_id']),
            esc_html($status['language'])
        );
        echo "<div class='notice $class is-dismissible'>$post_info</div>";
    }
}
add_action('admin_notices', 'libresign_show_github_action_status_notice');

/**
 * Settings link ad plugins page
 */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'libresign_add_settings_link');
function libresign_add_settings_link($links) {
    $settings_link = '<a href="options-general.php?page=libresign-config">Configurações</a>';
    array_unshift($links, $settings_link);
    return $links;
}

/**
 * Settings page
 */
add_action('admin_menu', function () {
    add_options_page(
        'Configurações do LibreSign',
        'LibreSign',
        'manage_options',
        'libresign-config',
        'libresign_config_page'
    );
});
function libresign_config_page() {
    if (!current_user_can('manage_options')) {
        wp_die(__('Você não tem permissão para acessar esta página.'));
    }

    ?>
    <div class="wrap">
        <h1>Configurações do LibreSign</h1>
        <form method="post" action="options.php">
            <?php
            settings_fields('libresign_settings_group');
            do_settings_sections('libresign_settings_group');
            $token = get_option('libresign_github_deploy_token');
            $repository = get_option('libresign_github_deploy_organization_repository');
            ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">GitHub deploy token</th>
                    <td>
                        <input
                            type="password"
                            name="libresign_github_deploy_token"
                            value=""
                            placeholder="<?php echo $token ? '•••••••••• (altere aqui)' : ''; ?>"
                            class="regular-text"
                        />
                        <p class="description">Este token será usado para acionar o deploy do site via GitHub Actions.</p>
                        <pre>
                        🛠 Passo a passo:

                            Vá para https://github.com/settings/tokens

                            Clique em "Generate new token (classic)"

                            Preencha os campos:
                                Note: Deploy trigger for LibreSign site
                                Expiration: (escolha conforme o necessário)
                                Select scopes:
                                    repo:
                                        repo_deployment, public_repo

                            Clique em Generate token e copie o token (você não poderá vê-lo novamente).

                            Cole esse token no campo de configuração no seu plugin do WordPress.
                        </pre>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Organização / Repositório</th>
                    <td>
                        <input
                            type="text"
                            name="libresign_github_deploy_organization_repository"
                            value="<?php echo esc_attr($repository); ?>"
                            placeholder="Ex: LibreSign/site"
                            class="regular-text"
                        />
                        <p class="description">Exemplo: <code>LibreSign/site</code></p>
                    </td>
                </tr>
            </table>
            <?php submit_button('Salvar configurações'); ?>
        </form>
    </div>
    <?php
}

/**
 * Encode the deploy token at database
 */
add_action('admin_init', function () {
    register_setting('libresign_settings_group', 'libresign_github_deploy_token', [
        'type' => 'string',
        'sanitize_callback' => function ($value) {
            if (!empty(trim($value))) {
                $key = hash('sha256', AUTH_KEY . SECURE_AUTH_SALT);
                $iv = substr(hash('sha256', NONCE_SALT), 0, 16);
                return base64_encode(openssl_encrypt($value, 'AES-256-CBC', $key, 0, $iv));
            }
            return get_option('libresign_github_deploy_token');
        },
    ]);
    register_setting('libresign_settings_group', 'libresign_github_deploy_organization_repository', [
        'type' => 'string',
        'sanitize_callback' => 'sanitize_text_field',
    ]);
});

/**
 * Return the WordPress version to be possible use the right assets when deploy
 */
add_action('rest_api_init', function () {
    register_rest_route('libresign/v1', '/version', [
        'methods' => 'GET',
        'callback' => function () {
            global $wp_version;
            return rest_ensure_response(['version' => $wp_version]);
        },
        'permission_callback' => '__return_true',
    ]);
});