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

const LIBRESIGN_WP_REWRITE_VERSION = '9';
const LIBRESIGN_FAQ_URL = 'https://libresign.coop/faq/';

/**
 * Get the WooCommerce My Account page ID.
 */
function libresign_get_my_account_page_id() {
    if ( ! function_exists( 'wc_get_page_id' ) ) {
        return 0;
    }

    return (int) wc_get_page_id( 'myaccount' );
}

/**
 * Check whether My Account is configured as the front page.
 */
function libresign_is_my_account_front_page() {
    $myaccount_page_id = libresign_get_my_account_page_id();
    $front_page_id     = (int) get_option( 'page_on_front' );

    return $myaccount_page_id > 0 && $myaccount_page_id === $front_page_id;
}

/**
 * Resolve a translated page ID when Polylang is active.
 */
function libresign_get_translated_page_id( $page_id, $language = '' ) {
    $page_id = (int) $page_id;

    if ( $page_id <= 0 ) {
        return 0;
    }

    if ( '' !== $language && function_exists( 'pll_get_post' ) ) {
        $translated_page_id = (int) pll_get_post( $page_id, $language );

        if ( $translated_page_id > 0 ) {
            return $translated_page_id;
        }
    }

    return $page_id;
}

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

require_once __DIR__ . '/includes/site-fragment-sync.php';
require_once __DIR__ . '/includes/github-site-webhook.php';
require_once __DIR__ . '/includes/account-navigation.php';


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
 * Trigger the site deploy workflow through GitHub's repository dispatch API.
 *
 * @return array<string, mixed>|WP_Error
 */
function libresign_dispatch_github_site_deploy() {
    $deploy_token = function_exists('libresign_decrypt_plugin_secret')
        ? libresign_decrypt_plugin_secret(get_option('libresign_github_deploy_token', ''))
        : '';
    $repository = trim((string) get_option('libresign_github_deploy_organization_repository', ''));

    if ('' === $deploy_token || '' === $repository) {
        return new WP_Error(
            'libresign_github_deploy_configuration_missing',
            __('Configure o token e o repositório do GitHub antes de executar o deploy.', 'libresign-wp-customizations')
        );
    }

    if (!preg_match('/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/', $repository)) {
        return new WP_Error(
            'libresign_github_deploy_repository_invalid',
            __('O repositório deve estar no formato organização/repositório.', 'libresign-wp-customizations')
        );
    }

    $response = wp_remote_post('https://api.github.com/repos/' . $repository . '/dispatches', [
        'body'        => wp_json_encode(['event_type' => 'deploy-site']),
        'headers'     => [
            'Authorization' => 'Bearer ' . $deploy_token,
            'Accept'         => 'application/vnd.github+json',
            'Content-Type'   => 'application/json',
            'User-Agent'     => 'LibreSign WordPress Plugin',
        ],
        'timeout'     => 15,
    ]);

    if (is_wp_error($response)) {
        return $response;
    }

    $code = (int) wp_remote_retrieve_response_code($response);
    if ($code < 200 || $code >= 300) {
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $message = is_array($body) && !empty($body['message'])
            ? (string) $body['message']
            : sprintf(__('O GitHub respondeu com HTTP %d.', 'libresign-wp-customizations'), $code);

        $message = sprintf(__('GitHub HTTP %1$d: %2$s', 'libresign-wp-customizations'), $code, $message);

        return new WP_Error('libresign_github_deploy_failed', $message, ['status' => $code]);
    }

    return ['code' => $code, 'repository' => $repository];
}

/**
 * Deploy the site after changing a post to publish.
 */
function libresign_trigger_github_action_on_publish($new_status, $old_status, $post) {
    if (($new_status === 'publish' || $old_status === 'publish') && $post->post_type === 'post') {
        $result = libresign_dispatch_github_site_deploy();
        $repository = get_option('libresign_github_deploy_organization_repository');

        if (is_wp_error($result)) {
            $status_data = [
                'type'    => 'error',
                'message' => 'Erro ao acionar deploy.<br />' . esc_html($result->get_error_message()),
            ];
        } else {
            $status_data = [
                'type'    => 'success',
                'message' => 'Ação de deploy enviada com sucesso. Acompanhe <a href="' . esc_url('https://github.com/' . $repository . '/actions') . '" target="_blank" rel="noopener noreferrer">aqui</a>',
            ];
        }

        $post_data = [
            'post_id'    => $post->ID,
            'post_title' => get_the_title($post->ID),
            'language'   => function_exists('pll_get_post_language') ? pll_get_post_language($post->ID) : 'indefinido',
        ];
        $post_data = array_merge($post_data, $status_data);

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
 * Run the same GitHub dispatch used by post publishing from the settings page.
 */
function libresign_handle_manual_github_deploy() {
    if (!current_user_can('manage_options')) {
        wp_die(__('Você não tem permissão para executar o deploy.', 'libresign-wp-customizations'));
    }

    check_admin_referer('libresign_manual_github_deploy');

    $result = libresign_dispatch_github_site_deploy();
    $repository = get_option('libresign_github_deploy_organization_repository');
    if (is_wp_error($result)) {
        $status = [
            'type'        => 'error',
            'post_title'  => 'Deploy manual',
            'post_id'     => 0,
            'language'    => '',
            'message'     => 'Erro ao acionar deploy.<br />' . esc_html($result->get_error_message()),
        ];
    } else {
        $status = [
            'type'        => 'success',
            'post_title'  => 'Deploy manual',
            'post_id'     => 0,
            'language'    => '',
            'message'     => 'Ação de deploy enviada com sucesso. Acompanhe <a href="' . esc_url('https://github.com/' . $repository . '/actions') . '" target="_blank" rel="noopener noreferrer">as execuções no GitHub</a>.',
        ];
    }

    $transient_key = 'libresign_github_action_status_' . get_current_user_id();
    $status_list = get_transient($transient_key);
    if (!is_array($status_list)) {
        $status_list = [];
    }
    $status_list[] = $status;
    set_transient($transient_key, $status_list, 60);

    wp_safe_redirect(admin_url('options-general.php?page=libresign-config'));
    exit;
}
add_action('admin_post_libresign_manual_github_deploy', 'libresign_handle_manual_github_deploy');

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
            $webhook_secret = get_option('libresign_github_webhook_secret');
            $site_origin = get_option('libresign_site_origin', 'https://libresign.coop');
            $workflow_name = get_option('libresign_site_deploy_workflow_name', 'pages build and deployment');
            $branch_name = get_option('libresign_site_deploy_branch_name', 'gh-pages');
            $webhook_endpoint = function_exists('libresign_github_site_webhook_endpoint_url')
                ? libresign_github_site_webhook_endpoint_url()
                : '';
            $last_sync = get_option('libresign_site_fragment_last_sync');
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
                        <p class="description">Exemplo: <code>LibreSign/site</code>. Este valor também é usado para validar o repositório recebido pela webhook do GitHub.</p>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Teste de deploy</th>
                    <td>
                        <?php
                        $manual_deploy_url = wp_nonce_url(
                            admin_url('admin-post.php?action=libresign_manual_github_deploy'),
                            'libresign_manual_github_deploy'
                        );
                        ?>
                        <a class="button button-secondary" href="<?php echo esc_url($manual_deploy_url); ?>">Executar deploy manualmente</a>
                        <p class="description">Dispara o evento <code>deploy-site</code> no repositório configurado, sem publicar um post. Use para testar o token, o repositório e o workflow do GitHub Actions.</p>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Webhook de deploy do site</th>
                    <td>
                        <input
                            type="text"
                            value="<?php echo esc_attr($webhook_endpoint); ?>"
                            class="regular-text code"
                            readonly
                        />
                        <p class="description">Configure uma webhook de repositório no GitHub para o evento <code>workflow_run</code> usando esta URL. O plugin sincroniza fragmentos apenas quando o workflow configurado abaixo conclui com sucesso na branch <code>main</code>.</p>
                        <?php if (is_array($last_sync) && !empty($last_sync['updated_at'])) : ?>
                            <p class="description">Última sincronização: <strong><?php echo esc_html((string) $last_sync['updated_at']); ?></strong> (status: <strong><?php echo esc_html((string) ($last_sync['status'] ?? '')); ?></strong>).</p>
                        <?php endif; ?>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Segredo da webhook do GitHub</th>
                    <td>
                        <input
                            type="password"
                            name="libresign_github_webhook_secret"
                            value=""
                            placeholder="<?php echo $webhook_secret ? '•••••••••• (altere aqui)' : ''; ?>"
                            class="regular-text"
                        />
                        <p class="description">Use o mesmo segredo configurado na webhook do repositório <code>LibreSign/site</code>.</p>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Origem do site estático</th>
                    <td>
                        <input
                            type="url"
                            name="libresign_site_origin"
                            value="<?php echo esc_attr((string) $site_origin); ?>"
                            placeholder="https://libresign.coop"
                            class="regular-text"
                        />
                        <p class="description">URL usada para buscar os fragmentos publicados em <code>/fragments/...</code> após o deploy de produção.</p>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Workflow monitorado</th>
                    <td>
                        <input
                            type="text"
                            name="libresign_site_deploy_workflow_name"
                            value="<?php echo esc_attr((string) $workflow_name); ?>"
                            placeholder="pages build and deployment"
                            class="regular-text"
                        />
                        <p class="description">Nome exato do workflow do GitHub que representa o deploy de produção. Use <code>pages build and deployment</code> para sincronizar apenas após o GitHub Pages estar ao vivo.</p>
                    </td>
                </tr>

                <tr valign="top">
                    <th scope="row">Branch monitorada</th>
                    <td>
                        <input
                            type="text"
                            name="libresign_site_deploy_branch_name"
                            value="<?php echo esc_attr((string) $branch_name); ?>"
                            placeholder="gh-pages"
                            class="regular-text"
                        />
                        <p class="description">Branch esperada para o workflow monitorado. Use <code>gh-pages</code> para o workflow <code>pages build and deployment</code>.</p>
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
    register_setting('libresign_settings_group', 'libresign_github_webhook_secret', [
        'type' => 'string',
        'sanitize_callback' => function ($value) {
            if (!empty(trim($value))) {
                $key = hash('sha256', AUTH_KEY . SECURE_AUTH_SALT);
                $iv = substr(hash('sha256', NONCE_SALT), 0, 16);
                return base64_encode(openssl_encrypt($value, 'AES-256-CBC', $key, 0, $iv));
            }
            return get_option('libresign_github_webhook_secret');
        },
    ]);
    register_setting('libresign_settings_group', 'libresign_site_origin', [
        'type' => 'string',
        'sanitize_callback' => function ($value) {
            $value = rtrim(esc_url_raw(trim((string) $value)), '/');
            return '' === $value ? 'https://libresign.coop' : $value;
        },
    ]);
    register_setting('libresign_settings_group', 'libresign_site_deploy_workflow_name', [
        'type' => 'string',
        'sanitize_callback' => function ($value) {
            $value = trim(sanitize_text_field((string) $value));
            return '' === $value ? 'pages build and deployment' : $value;
        },
    ]);
    register_setting('libresign_settings_group', 'libresign_site_deploy_branch_name', [
        'type' => 'string',
        'sanitize_callback' => function ($value) {
            $value = trim(sanitize_text_field((string) $value));
            return '' === $value ? 'gh-pages' : $value;
        },
    ]);
});

/**
 * Register WooCommerce account endpoints at the site root when the account page is the front page.
 */
function libresign_register_root_my_account_endpoints() {
    if ( ! function_exists( 'wc_get_page_id' ) || ! function_exists( 'WC' ) ) {
        return;
    }

    $myaccount_page_id = libresign_get_my_account_page_id();
    if ( ! libresign_is_my_account_front_page() ) {
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
                    'index.php?lang=$matches[1]&page_id=' . libresign_get_translated_page_id( $myaccount_page_id, '$matches[1]' ) . '&' . $query_var . '=$matches[2]',
                    'top'
                );
            }
        }
    }
}
add_action( 'init', 'libresign_register_root_my_account_endpoints', 20 );

/**
 * Register compatibility rewrites for the standard WooCommerce My Account path.
 *
 * When My Account is used as the front page, WooCommerce's default /my-account/
 * permalink is not generated automatically. Keep it working as an alias so
 * existing links and language-prefixed routes do not break.
 */
function libresign_register_my_account_page_aliases() {
    if ( ! function_exists( 'WC' ) ) {
        return;
    }

    if ( ! libresign_is_my_account_front_page() ) {
        return;
    }

    $myaccount_page_id = libresign_get_my_account_page_id();

    if ( $myaccount_page_id <= 0 ) {
        return;
    }

    add_rewrite_rule(
        '^my-account/?$',
        'index.php?page_id=' . $myaccount_page_id,
        'top'
    );

    if ( function_exists( 'pll_languages_list' ) ) {
        $languages = pll_languages_list( array( 'fields' => 'slug' ) );

        if ( is_array( $languages ) && ! empty( $languages ) ) {
            foreach ( $languages as $language ) {
                $translated_page_id = libresign_get_translated_page_id( $myaccount_page_id, $language );

                add_rewrite_rule(
                    '^' . preg_quote( $language, '/' ) . '/my-account/?$',
                    'index.php?lang=' . $language . '&page_id=' . $translated_page_id,
                    'top'
                );
            }
        }
    }
}
add_action( 'init', 'libresign_register_my_account_page_aliases', 19 );

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
    libresign_register_my_account_page_aliases();
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

    if ( ! libresign_is_my_account_front_page() ) {
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

    if ( 'my-account' === $first_slug ) {
        return true;
    }

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
 * Nextcloud URL reachable from the customer's browser.
 *
 * `nextcloud_api_host` is used by woocommerce-nextcloud-admin-group-manager for
 * server-to-server OCS calls, so in local dev it points to host.docker.internal,
 * which browsers can't resolve. `nextcloud_public_host` overrides it for links
 * rendered here; falls back to `nextcloud_api_host` when unset (production).
 */
function libresign_get_nextcloud_public_host() {
    $public_host = trim( (string) get_option( 'nextcloud_public_host' ) );

    if ( '' !== $public_host ) {
        return $public_host;
    }

    return trim( (string) get_option( 'nextcloud_api_host' ) );
}

/**
 * Render a CTA on every customer account screen that points to the Nextcloud instance.
 */
function libresign_render_nextcloud_account_button() {
    if ( ! function_exists( 'is_account_page' ) || ! is_account_page() || ! function_exists( 'is_user_logged_in' ) || ! is_user_logged_in() ) {
        return;
    }

    $nextcloud_host = libresign_get_nextcloud_public_host();

    if ( '' === $nextcloud_host ) {
        return;
    }

    $faq_link = sprintf(
        '<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
        esc_url( LIBRESIGN_FAQ_URL ),
        esc_html__( 'FAQ', 'libresign-wp-customizations' )
    );

    printf(
        '<div class="libresign-nextcloud-account-cta"><p>%s</p><p><a class="wp-block-button__link wp-element-button" href="%s" target="_blank" rel="noopener noreferrer">%s</a></p><p>%s</p></div>',
        esc_html__( 'Use as mesmas credenciais do WordPress para acessar o sistema de assinaturas.', 'libresign-wp-customizations' ),
        esc_url( $nextcloud_host ),
        esc_html__( 'Ir para o sistema de assinaturas', 'libresign-wp-customizations' ),
        sprintf(
            /* translators: %s: link to the FAQ page */
            esc_html__( 'Se precisar de ajuda, veja nosso %s.', 'libresign-wp-customizations' ),
            $faq_link
        )
    );
}
add_action( 'woocommerce_before_account_navigation', 'libresign_render_nextcloud_account_button', 20 );

/**
 * Confirmation strings for each subscription status change that requires an extra step.
 */
function libresign_get_subscription_confirmation_strings( $new_status ) {
    $strings = array(
        'cancelled' => array(
            'question' => __( 'Are you sure you want to cancel your subscription? This action cannot be undone.', 'libresign-wp-customizations' ),
            'confirm'  => __( 'Yes, cancel subscription', 'libresign-wp-customizations' ),
            'dismiss'  => __( 'No, keep subscription', 'libresign-wp-customizations' ),
        ),
        'active' => array(
            'question' => __( 'Are you sure you want to reactivate your subscription?', 'libresign-wp-customizations' ),
            'confirm'  => __( 'Yes, reactivate subscription', 'libresign-wp-customizations' ),
            'dismiss'  => __( 'No, go back', 'libresign-wp-customizations' ),
        ),
    );

    return $strings[ $new_status ] ?? null;
}

/**
 * Resolve a subscription the current user is allowed to update to the given status, or null.
 */
function libresign_get_subscription_for_status_change( $subscription_id, $new_status ) {
    if ( ! function_exists( 'wcs_get_subscription' ) ) {
        return null;
    }

    $subscription = wcs_get_subscription( absint( $subscription_id ) );

    if ( ! $subscription
        || ! current_user_can( 'edit_shop_subscription_status', $subscription->get_id() )
        || ! $subscription->can_be_updated_to( $new_status )
    ) {
        return null;
    }

    return $subscription;
}

/**
 * Intercept unconfirmed status change requests before WCS_User_Change_Status_Handler
 * (wp_loaded, priority 100) and redirect to the confirmation prompt instead.
 */
function libresign_intercept_subscription_status_change() {
    if ( ! isset( $_GET['change_subscription_to'], $_GET['subscription_id'], $_GET['_wpnonce'] )
        || ! function_exists( 'wc_clean' )
    ) {
        return;
    }

    if ( ! empty( $_GET['libresign_change_confirmed'] ) ) {
        return;
    }

    $new_status = wc_clean( wp_unslash( $_GET['change_subscription_to'] ) );

    if ( ! libresign_get_subscription_confirmation_strings( $new_status ) ) {
        return;
    }

    $subscription = libresign_get_subscription_for_status_change( $_GET['subscription_id'], $new_status );
    $nonce        = wc_clean( wp_unslash( $_GET['_wpnonce'] ) );

    if ( ! $subscription
        || ! wp_verify_nonce( $nonce, $subscription->get_id() . $subscription->get_status() )
    ) {
        return;
    }

    wp_safe_redirect(
        add_query_arg(
            array(
                'libresign_confirm_change'       => $new_status,
                'libresign_confirm_subscription' => $subscription->get_id(),
                '_wpnonce'                       => $nonce,
            ),
            $subscription->get_view_order_url()
        )
    );
    exit;
}
add_action( 'wp_loaded', 'libresign_intercept_subscription_status_change', 99 );

/**
 * Show the status change confirmation prompt on the subscription page.
 */
function libresign_render_subscription_change_confirmation() {
    if ( empty( $_GET['libresign_confirm_change'] )
        || empty( $_GET['libresign_confirm_subscription'] )
        || empty( $_GET['_wpnonce'] )
        || ! function_exists( 'wc_clean' )
        || ! function_exists( 'is_account_page' )
        || ! is_account_page()
    ) {
        return;
    }

    $new_status = wc_clean( wp_unslash( $_GET['libresign_confirm_change'] ) );
    $strings    = libresign_get_subscription_confirmation_strings( $new_status );

    if ( ! $strings ) {
        return;
    }

    $subscription = libresign_get_subscription_for_status_change( $_GET['libresign_confirm_subscription'], $new_status );
    $nonce        = wc_clean( wp_unslash( $_GET['_wpnonce'] ) );

    if ( ! $subscription
        || ! wp_verify_nonce( $nonce, $subscription->get_id() . $subscription->get_status() )
    ) {
        return;
    }

    $confirm_url = add_query_arg(
        array(
            'subscription_id'            => $subscription->get_id(),
            'change_subscription_to'     => $new_status,
            'libresign_change_confirmed' => '1',
            '_wpnonce'                   => $nonce,
        ),
        $subscription->get_view_order_url()
    );

    $message = sprintf(
        '<span class="libresign-confirm-question">%s</span><span class="libresign-confirm-actions"><a href="%s" class="button">%s</a> <a href="%s" class="button">%s</a></span>',
        esc_html( $strings['question'] ),
        esc_url( $confirm_url ),
        esc_html( $strings['confirm'] ),
        esc_url( $subscription->get_view_order_url() ),
        esc_html( $strings['dismiss'] )
    );

    wc_add_notice( $message, 'notice' );
}
add_action( 'template_redirect', 'libresign_render_subscription_change_confirmation' );

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
