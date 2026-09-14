# LibreSign WordPress customizations

Customizations at WordPress relative to website libresign.coop

## Install

- Clone this repository at your plugin folder
- Enable this plugin

### Configure deploy

- Go to Configurations of this plugin
- Create the GitHub token and add at configuration page
- Set the organization and repository that have the deploy action

## Architecture

`src/` holds the decisions and `includes/` plus the main plugin file hold the
wiring: the hooks, the options and the effects. A decision receives values and
returns values — the navigation receives the query vars instead of reading
`global $wp`, the webhook gate receives the headers instead of a
`WP_REST_Request` — so it is covered by a data provider and no test double.

```
src/
├── Account/Navigation.php        # entries, labels and the active one
├── Account/RootEndpoint.php      # account screens served from the site root
├── Github/DeployDispatch.php     # when publishing asks GitHub for a deploy
├── Github/SiteDeploy.php         # which run publishes the site
├── Github/WebhookDecision.php    # what to answer a delivery
├── Github/WebhookGate.php        # inspection of a delivery
├── Github/WebhookRequest.php     # headers and body of a delivery
├── Github/WebhookSignature.php   # the HMAC GitHub signs with
├── Github/WorkflowRun.php        # the run a payload describes
├── Settings/Secret.php           # the cipher of the token and the secret
└── Subscription/StatusChange.php # changes that ask for a confirmation
```

The plugin is installed by cloning the repository, so Composer never runs on the
server: `src/Autoloader.php` maps the namespace to `src/` and is the only file
the plugin requires by hand.

## Development

Every check is a Composer script:

```bash
composer lint   # php -l on every file
composer cs     # PHPCS
composer stan   # PHPStan
composer test   # PHPUnit
composer ci     # all of the above, in this order
```

### Tests

`composer install` brings in WordPress itself (`vendor/wordpress`) and the
WordPress test suite, so the only thing the tests need from outside is a
MySQL/MariaDB server and a database they are allowed to wipe on every run.

| Variable | Default |
|---|---|
| `WP_TESTS_DB_NAME` | `wordpress_test` |
| `WP_TESTS_DB_USER` | `root` |
| `WP_TESTS_DB_PASSWORD` | `root` |
| `WP_TESTS_DB_HOST` | `mariadb` |
| `WP_TESTS_TABLE_PREFIX` | `wptests_` |
| `WP_CORE_DIR` | `vendor/wordpress` |

The defaults are the ones of the local SaaS stack, where both the database and
Composer already live inside the containers:

```bash
docker exec wordpress-docker-mariadb-1 \
  mariadb -uroot -proot -e 'CREATE DATABASE IF NOT EXISTS wordpress_test;'

docker exec -w /var/www/html/wp-content/plugins/libresign-wp-customizations \
  wordpress-docker-wordpress-1 composer test
```

`tests/Unit/` mirrors `src/` and `tests/Integration/` mirrors the plugin files,
in both cases file by file with `Test.php` appended:
`src/Github/WebhookGate.php` is covered by
`tests/Unit/Github/WebhookGateTest.php`, and the endpoint wiring it serves,
`includes/github-site-webhook.php`, by
`tests/Integration/Includes/GithubSiteWebhookTest.php`. A decision is covered by
a unit test, and the wiring by an integration test going through WordPress:
options, hooks, the REST server or the database.

Nothing is mocked. Outgoing HTTP is answered through the `pre_http_request`
filter (`tests/Support/FakeHttp.php`), which is WordPress' own extension point,
and any request that is not answered that way fails the test instead of
reaching the network.

WooCommerce is not installed in the test suite, so the screens that only exist
with WooCommerce loaded — the root account endpoints, the invoice title, the
addresses redirect and the subscription confirmation flow — are still uncovered.
