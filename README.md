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
composer lint      # php -l on every file
composer cs        # PHPCS
composer stan      # PHPStan
composer test      # PHPUnit
composer coverage  # PHPUnit with the coverage floor enforced
composer ci        # all of the above, in this order
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

WooCommerce is not installed in this suite, so the screens that only exist with
WooCommerce loaded are covered by the browser tests instead.

`tests/Unit/StructureTest.php` is what keeps that convention: a file of the
plugin without the test named after it, and a test named after a file that no
longer exists, both fail the suite.

### Coverage

`composer coverage` runs the suite with Xdebug collecting coverage and compares
the result with `coverage-floor.txt`, which holds the line coverage the
repository has already reached:

```bash
docker exec -w /var/www/html/wp-content/plugins/libresign-wp-customizations \
  wordpress-docker-wordpress-1 composer coverage
```

The floor only goes up. Coverage below it fails, and so does coverage a full
point above it, with the number to write in the file — a change that covers
more is a change that raises the floor, and nothing silently gives the ground
back.

The report of the previous run is dropped before the suite starts, so a run
without a coverage driver — which PHPUnit only warns about — is caught instead
of being graded on numbers it did not produce.

### Browser tests

`tests/E2E/` mirrors `src/` the same way, with `.spec.ts` in place of
`Test.php`: `src/Account/Navigation.php` is covered end to end by
`tests/E2E/Account/Navigation.spec.ts`. What lives here is what PHPUnit cannot
reach without WooCommerce, the rewrite rules and a browser — the account
navigation, the account screens served from the site root and the confirmation
of a subscription status change.

The suite runs against a WordPress that is already up, described by four
variables:

| Variable | Default |
|---|---|
| `WP_BASE_URL` | `http://localhost` |
| `WP_CLI` | `docker exec -i -u www-data wordpress-docker-wordpress-1 wp --path=/var/www/html` |
| `WP_E2E_CUSTOMER_PASSWORD` | `libresign-e2e` |
| `WP_E2E_ALLOW_ANY_SITE` | unset |

The defaults are the local SaaS stack again, so there it takes no arguments:

```bash
npm install
npx playwright install chromium
npm run test:e2e
```

`tests/E2E/support/seed.php` puts the site in the state the specs expect, and
runs again before each test that changes the subscription. It is destructive and
nothing is restored afterwards: it makes My Account the front page, rebuilds the
rewrite rules, and creates `libresign_e2e_customer` with the password above,
which this repository publishes. That is why it refuses to run against anything
but `localhost` unless `WP_E2E_ALLOW_ANY_SITE=1` says so — point it at a site you
can throw away, never at production or staging.

Anywhere else, point the first two at the site under test. `.wp-env.json`
describes a disposable one, which is what CI runs:

```bash
npm run env:start
WP_BASE_URL=http://localhost:8888 WP_CLI="npx wp-env run cli wp" npm run test:e2e
```

WooCommerce only offers the billing screen when one of the available gateways
keeps payment methods. The local stack has Stripe for that; `.wp-env.json` maps
a mu-plugin that declares one.
