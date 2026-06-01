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
 * Text Domain:       libresign-wp-customizations
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * GitHub Plugin URI: https://github.com/LibreSign/libresign-wp-customizations
 */

defined( 'ABSPATH' ) || exit;

const LIBRESIGN_WP_REWRITE_VERSION = '4';

/**
 * Load plugin translations.
 */
add_action( 'plugins_loaded', function () {
    load_plugin_textdomain(
        'libresign-wp-customizations',
        false,
        dirname( plugin_basename( __FILE__ ) ) . '/languages'
    );
} );


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
                    'message' => 'Ação de deploy enviada com sucesso. Acompanhe <a href="https://github.com/' . $organizationRepository.'/actions" target="_blank">aqui</a>',
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
 * Register WooCommerce account endpoints at the site root when the account page is the front page.
 */
function libresign_register_root_my_account_endpoints() {
    if ( ! function_exists( 'wc_get_page_id' ) || ! function_exists( 'WC' ) ) {
        return;
    }

    $myaccount_page_id = (int) wc_get_page_id( 'myaccount' );
    $front_page_id     = (int) get_option( 'page_on_front' );

    if ( $myaccount_page_id <= 0 || $myaccount_page_id !== $front_page_id ) {
        return;
    }

    $query_vars = WC()->query->get_query_vars();

    foreach ( $query_vars as $query_var ) {
        if ( empty( $query_var ) ) {
            continue;
        }

        add_rewrite_endpoint( $query_var, EP_ROOT );
        add_rewrite_rule(
            '^' . preg_quote( $query_var, '/' ) . '(?:/(.*))?/?$',
            'index.php?page_id=' . $myaccount_page_id . '&' . $query_var . '=$matches[1]',
            'top'
        );
    }

    if ( function_exists( 'pll_languages_list' ) ) {
        $languages = pll_languages_list( [ 'fields' => 'slug' ] );

        if ( is_array( $languages ) && ! empty( $languages ) ) {
            $language_pattern = implode( '|', array_map( 'preg_quote', $languages ) );

            foreach ( $query_vars as $query_var ) {
                if ( empty( $query_var ) ) {
                    continue;
                }

                add_rewrite_rule(
                    '^(' . $language_pattern . ')/' . preg_quote( $query_var, '/' ) . '(?:/(.*))?/?$',
                    'index.php?lang=$matches[1]&page_id=' . $myaccount_page_id . '&' . $query_var . '=$matches[2]',
                    'top'
                );
            }
        }
    }
}
add_action( 'init', 'libresign_register_root_my_account_endpoints', 20 );

/**
 * Register explicit checkout endpoint rewrites so order-pay and order-received are not parsed as posts.
 */
function libresign_register_checkout_endpoints() {
    if ( ! function_exists( 'wc_get_page_id' ) || ! function_exists( 'WC' ) ) {
        return;
    }

    $checkout_page_id = (int) wc_get_page_id( 'checkout' );

    if ( $checkout_page_id <= 0 ) {
        return;
    }

    $checkout_slug = get_post_field( 'post_name', $checkout_page_id );

    if ( empty( $checkout_slug ) ) {
        return;
    }

    $query_vars = WC()->query->get_query_vars();
    $endpoints  = array_intersect_key(
        $query_vars,
        array(
            'order-pay'      => true,
            'order-received' => true,
        )
    );

    foreach ( $endpoints as $key => $query_var ) {
        if ( empty( $query_var ) ) {
            continue;
        }

        add_rewrite_rule(
            '^' . preg_quote( $checkout_slug, '/' ) . '/' . preg_quote( $query_var, '/' ) . '(?:/(.*))?/?$',
            'index.php?page_id=' . $checkout_page_id . '&' . $query_var . '=$matches[1]',
            'top'
        );
    }

    if ( function_exists( 'pll_languages_list' ) ) {
        $languages = pll_languages_list( array( 'fields' => 'slug' ) );

        if ( is_array( $languages ) && ! empty( $languages ) ) {
            $language_pattern = implode( '|', array_map( 'preg_quote', $languages ) );

            foreach ( $endpoints as $key => $query_var ) {
                if ( empty( $query_var ) ) {
                    continue;
                }

                add_rewrite_rule(
                    '^(' . $language_pattern . ')/' . preg_quote( $checkout_slug, '/' ) . '/' . preg_quote( $query_var, '/' ) . '(?:/(.*))?/?$',
                    'index.php?lang=$matches[1]&page_id=' . $checkout_page_id . '&' . $query_var . '=$matches[2]',
                    'top'
                );
            }
        }
    }
}
add_action( 'init', 'libresign_register_checkout_endpoints', 20 );

/**
 * Flush rewrite rules once after endpoint registration changes.
 */
function libresign_maybe_flush_root_my_account_endpoints() {
    $stored_version = get_option( 'libresign_root_my_account_rewrite_version', '' );

    if ( LIBRESIGN_WP_REWRITE_VERSION === $stored_version ) {
        return;
    }

    libresign_register_root_my_account_endpoints();
    flush_rewrite_rules( false );
    update_option( 'libresign_root_my_account_rewrite_version', LIBRESIGN_WP_REWRITE_VERSION );
}
add_action( 'init', 'libresign_maybe_flush_root_my_account_endpoints', 99 );

/**
 * Check whether the current request is a root-level My Account endpoint while My Account is the front page.
 */
function libresign_is_root_my_account_endpoint_request() {
    if ( ! function_exists( 'wc_get_page_id' ) || ! function_exists( 'WC' ) ) {
        return false;
    }

    $myaccount_page_id = (int) wc_get_page_id( 'myaccount' );
    $front_page_id     = (int) get_option( 'page_on_front' );

    if ( $myaccount_page_id <= 0 || $myaccount_page_id !== $front_page_id ) {
        return false;
    }

    $request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
    $request_path = trim( (string) wp_parse_url( $request_uri, PHP_URL_PATH ), '/' );

    if ( '' === $request_path ) {
        return false;
    }

    $segments   = explode( '/', $request_path );
    $first_slug = reset( $segments );
    $query_vars = WC()->query->get_query_vars();

    foreach ( $query_vars as $query_var ) {
        if ( ! empty( $query_var ) && $query_var === $first_slug ) {
            return true;
        }
    }

    return false;
}

/**
 * Prevent WordPress canonical redirects from collapsing root account endpoints back to the front page.
 *
 * When the My Account page is also the front page, requests like /lost-password/ or /payment-methods/
 * are valid WooCommerce endpoints and should not be redirected to /.
 */
function libresign_disable_canonical_redirect_for_root_my_account_endpoints( $redirect_url, $requested_url ) {
    if ( libresign_is_root_my_account_endpoint_request() ) {
        return false;
    }

    return $redirect_url;
}
add_filter( 'redirect_canonical', 'libresign_disable_canonical_redirect_for_root_my_account_endpoints', 10, 2 );

/**
 * Remove generic redirect handlers for root My Account endpoints before they run.
 */
function libresign_prevent_root_my_account_endpoint_redirects() {
    if ( ! libresign_is_root_my_account_endpoint_request() ) {
        return;
    }

    remove_action( 'template_redirect', 'redirect_canonical', 10 );
    remove_action( 'template_redirect', 'wp_old_slug_redirect', 10 );
    remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
    remove_action( 'template_redirect', 'wc_product_canonical_redirect', 5 );
}
add_action( 'template_redirect', 'libresign_prevent_root_my_account_endpoint_redirects', 0 );

/**
 * Render a CTA on every customer account screen that points to the Nextcloud instance.
 */
function libresign_render_nextcloud_account_button() {
    if ( ! function_exists( 'is_account_page' ) || ! is_account_page() || ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
        return;
    }

    $nextcloud_host = trim( (string) get_option( 'nextcloud_api_host' ) );

    if ( '' === $nextcloud_host ) {
        return;
    }

    printf(
        '<div class="libresign-nextcloud-account-cta" style="margin-top: 1.5rem; padding: 1rem; border: 1px solid currentColor; border-radius: 0.75rem;"><p style="margin: 0 0 0.75rem 0;">%s</p><p style="margin: 0;"><a class="wp-block-button__link wp-element-button is-style-outline" href="%s" target="_blank" rel="noopener noreferrer">%s</a></p></div>',
        esc_html__( 'Use as mesmas credenciais do WordPress para acessar o sistema de assinaturas.', 'libresign-wp-customizations' ),
        esc_url( $nextcloud_host ),
        esc_html__( 'Ir para o sistema de assinaturas', 'libresign-wp-customizations' )
    );
}
add_action( 'woocommerce_before_account_navigation', 'libresign_render_nextcloud_account_button', 20 );

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
