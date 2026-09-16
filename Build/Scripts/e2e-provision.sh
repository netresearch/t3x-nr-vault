#!/usr/bin/env bash
#
# Provision a TYPO3 installation with this extension for the Playwright E2E
# suite, outside DDEV. Used by .github/workflows/e2e.yml and runnable locally.
#
# The recipe mirrors .ddev/commands/web/install-v14 (the DDEV instance the specs
# were written against): a typo3/cms-base-distribution project, this checkout
# required through a path repository, `typo3 setup`, `extension:setup` and the
# demo seed. What differs is only what DDEV provides implicitly: the database
# host and the web server.
#
# The script provisions; it does not serve. It writes a router for PHP's
# built-in server next to the project, so serving is one command:
#
#   PHP_CLI_SERVER_WORKERS=8 php -S 127.0.0.1:8080 -t "$E2E_INSTANCE_DIR/public" "$E2E_INSTANCE_DIR/router.php"
#
# Environment:
#   E2E_INSTANCE_DIR     Target directory for the TYPO3 project (required, must not exist or be empty)
#   TYPO3_VERSION        Composer constraint for typo3/cms-core   (default: ^14.3)
#   E2E_DB_DRIVER        mysqli | sqlite                          (default: mysqli)
#   E2E_DB_HOST          (mysqli)                                 (default: 127.0.0.1)
#   E2E_DB_PORT          (mysqli)                                 (default: 3306)
#   E2E_DB_NAME          (mysqli)                                 (default: typo3)
#   E2E_DB_USER          (mysqli)                                 (default: root)
#   E2E_DB_PASSWORD      (mysqli)                                 (default: root)
#   E2E_ADMIN_USERNAME   Backend admin the specs log in as        (default: admin)
#   E2E_ADMIN_PASSWORD   Its password                             (default: Joh316!!, the DDEV default)
#
# The credentials are throwaway values for an ephemeral test instance, never
# secrets; the defaults match Tests/E2E/fixtures/auth.ts.

set -euo pipefail

: "${E2E_INSTANCE_DIR:?E2E_INSTANCE_DIR must name the directory to create the TYPO3 project in}"
TYPO3_VERSION="${TYPO3_VERSION:-^14.3}"
E2E_DB_DRIVER="${E2E_DB_DRIVER:-mysqli}"
E2E_ADMIN_USERNAME="${E2E_ADMIN_USERNAME:-admin}"
E2E_ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Joh316!!}"

EXTENSION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$TYPO3_VERSION" in
    *13*) DISTRIBUTION='^13.4' ;;
    *14*) DISTRIBUTION='^14.3' ;;
    *) echo "Unsupported TYPO3_VERSION '$TYPO3_VERSION' (expected a ^13.4 or ^14.3 constraint)" >&2; exit 1 ;;
esac

if [ -e "$E2E_INSTANCE_DIR" ] && [ -n "$(ls -A "$E2E_INSTANCE_DIR")" ]; then
    echo "E2E_INSTANCE_DIR '$E2E_INSTANCE_DIR' exists and is not empty" >&2
    exit 1
fi

echo "=== Creating typo3/cms-base-distribution:$DISTRIBUTION in $E2E_INSTANCE_DIR ==="
composer create-project "typo3/cms-base-distribution:$DISTRIBUTION" "$E2E_INSTANCE_DIR" \
    --no-install --no-interaction --no-progress

cd "$E2E_INSTANCE_DIR"

# A checkout is often a detached HEAD, from which composer cannot derive a
# version for a path repository. Pin one explicitly so the require below
# resolves the same way on a branch, a tag and a PR merge ref.
composer config repositories.nr_vault \
    "{\"type\":\"path\",\"url\":\"$EXTENSION_DIR\",\"options\":{\"symlink\":true,\"versions\":{\"netresearch/nr-vault\":\"dev-e2e\"}}}"
composer config --no-plugins audit.block-insecure false

echo "=== Requiring netresearch/nr-vault and typo3/cms-core:$TYPO3_VERSION ==="
composer require --no-update --no-interaction \
    "netresearch/nr-vault:dev-e2e" \
    "typo3/cms-core:$TYPO3_VERSION"
composer install --no-interaction --no-progress --prefer-dist

echo "=== Running typo3 setup ($E2E_DB_DRIVER) ==="
SETUP_ARGS=(
    --admin-username="$E2E_ADMIN_USERNAME"
    --admin-email=e2e@example.com
    --admin-user-password="$E2E_ADMIN_PASSWORD"
    --project-name='EXT:nr_vault E2E'
    --server-type=other
    --no-interaction
    --force
)
case "$E2E_DB_DRIVER" in
    mysqli)
        SETUP_ARGS+=(
            --driver=mysqli
            --host="${E2E_DB_HOST:-127.0.0.1}"
            --port="${E2E_DB_PORT:-3306}"
            --dbname="${E2E_DB_NAME:-typo3}"
            --username="${E2E_DB_USER:-root}"
            --password="${E2E_DB_PASSWORD:-root}"
        )
        ;;
    sqlite)
        # `--driver` takes the setup command's connection type, not the
        # Doctrine driver; the database file is derived under var/sqlite/.
        SETUP_ARGS+=(--driver=sqlite)
        ;;
    *)
        echo "Unsupported E2E_DB_DRIVER '$E2E_DB_DRIVER' (expected mysqli or sqlite)" >&2
        exit 1
        ;;
esac
vendor/bin/typo3 setup "${SETUP_ARGS[@]}"

# The instance is served on a loopback address, not a *.ddev.site host. Same
# override file install-v14 uses, so a re-run of `typo3 setup` keeps it.
cat > config/system/additional.php <<'PHP'
<?php
$GLOBALS['TYPO3_CONF_VARS']['SYS']['trustedHostsPattern'] = '(127\.0\.0\.1|localhost)(:\d+)?';
PHP

echo "=== Setting up extensions ==="
vendor/bin/typo3 extension:setup

# Same seed as install-v14. vault:seed-demo refuses to run in Production, which
# is the context the instance is served in.
echo "=== Seeding demo data ==="
TYPO3_CONTEXT=Development vendor/bin/typo3 vault:seed-demo

vendor/bin/typo3 cache:flush

# Router for PHP's built-in server. TYPO3 v12+ has no typo3/index.php: backend
# routes (/typo3/...) and frontend requests alike are dispatched by the single
# public/index.php, which is what the root .htaccess shipped by typo3/cms-install
# does for Apache — existing files are served as they are, everything else goes
# to index.php.
cat > router.php <<'PHP'
<?php
$path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$file = __DIR__ . '/public' . $path;
if ($path !== '/' && is_file($file) && !str_ends_with($file, '.php')) {
    return false;
}
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = __DIR__ . '/public/index.php';
$_SERVER['PHP_SELF'] = '/index.php';
chdir(__DIR__ . '/public');
require __DIR__ . '/public/index.php';
PHP

echo "=== TYPO3 $TYPO3_VERSION with nr_vault provisioned in $E2E_INSTANCE_DIR ==="
