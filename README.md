# LibreSign WordPress customizations

Customizations at WordPress relative to website libresign.coop

## Install

- Clone this repository at your plugin folder
- Enable this plugin

### Configure deploy

- Go to Configurations of this plugin
- Create the GitHub token and add at configuration page
- Set the organization and repository that have the deploy action

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

`tests/` mirrors the plugin file by file, with `Test.php` appended:
`includes/github-site-webhook.php` is covered by
`tests/Unit/Includes/GithubSiteWebhookTest.php` and
`tests/Integration/Includes/GithubSiteWebhookTest.php`. A file belongs to
`Unit/` when it only feeds values to a function and reads the returned value,
and to `Integration/` when it goes through WordPress: options, hooks, the REST
server or the database.

Nothing is mocked. Outgoing HTTP is answered through the `pre_http_request`
filter (`tests/Support/FakeHttp.php`), which is WordPress' own extension point,
and any request that is not answered that way fails the test instead of
reaching the network.

WooCommerce is not installed in the test suite, so the screens that only exist
with WooCommerce loaded — the root account endpoints, the invoice title, the
addresses redirect and the subscription confirmation flow — are still uncovered.
