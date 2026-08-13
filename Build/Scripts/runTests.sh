#!/usr/bin/env bash

#
# nr-vault test runner based on docker/podman.
# Following TYPO3 core testing conventions.
#

# Ensure cleanUp always runs: on normal exit (EXIT) and on forced termination (SIGINT/SIGTERM)
trap 'cleanUp; exit 2' SIGINT SIGTERM
trap 'cleanUp' EXIT

waitFor() {
    local HOST=${1}
    local PORT=${2}
    local TESTCOMMAND="
        COUNT=0;
        while ! nc -z ${HOST} ${PORT}; do
            if [ \"\${COUNT}\" -gt 10 ]; then
              echo \"Can not connect to ${HOST} port ${PORT}. Aborting.\";
              exit 1;
            fi;
            sleep 1;
            COUNT=\$((COUNT + 1));
        done;
    "
    ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name wait-for-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${IMAGE_ALPINE} /bin/sh -c "${TESTCOMMAND}"
    if [[ $? -gt 0 ]]; then
        kill -SIGINT -$$
    fi
}

waitForHttp() {
    local URL=${1}
    local MAX_ATTEMPTS=${2:-30}
    local TESTCOMMAND="
        COUNT=0;
        while ! wget -q --spider ${URL} 2>/dev/null; do
            if [ \"\${COUNT}\" -gt ${MAX_ATTEMPTS} ]; then
              echo \"HTTP endpoint ${URL} not available after ${MAX_ATTEMPTS} attempts. Aborting.\";
              exit 1;
            fi;
            sleep 1;
            COUNT=\$((COUNT + 1));
        done;
        echo \"HTTP endpoint ${URL} is ready.\";
    "
    ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name wait-for-http-${SUFFIX} ${IMAGE_ALPINE} /bin/sh -c "${TESTCOMMAND}"
    if [[ $? -gt 0 ]]; then
        kill -SIGINT -$$
    fi
}

cleanUp() {
    ATTACHED_CONTAINERS=$(${CONTAINER_BIN} ps --filter network=${NETWORK} --format='{{.Names}}' 2>/dev/null)
    for ATTACHED_CONTAINER in ${ATTACHED_CONTAINERS}; do
        ${CONTAINER_BIN} rm -f ${ATTACHED_CONTAINER} >/dev/null 2>&1
    done
    ${CONTAINER_BIN} network rm ${NETWORK} >/dev/null 2>&1
}

cleanCacheFiles() {
    echo -n "Clean caches ... "
    rm -rf \
        .Build/.cache \
        .php-cs-fixer.cache \
        Build/.phpunit.cache
    echo "done"
}

cleanRenderedDocumentationFiles() {
    echo -n "Clean rendered documentation files ... "
    rm -rf \
        Documentation-GENERATED-temp
    echo "done"
}

handleDbmsOptions() {
    # -a, -d, -i depend on each other. Validate input combinations and set defaults.
    case ${DBMS} in
        mariadb)
            [ -z "${DATABASE_DRIVER}" ] && DATABASE_DRIVER="mysqli"
            if [ "${DATABASE_DRIVER}" != "mysqli" ] && [ "${DATABASE_DRIVER}" != "pdo_mysql" ]; then
                echo "Invalid combination -d ${DBMS} -a ${DATABASE_DRIVER}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            [ -z "${DBMS_VERSION}" ] && DBMS_VERSION="10.11"
            if ! [[ ${DBMS_VERSION} =~ ^(10.5|10.6|10.11|11.0|11.4)$ ]]; then
                echo "Invalid combination -d ${DBMS} -i ${DBMS_VERSION}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            ;;
        mysql)
            [ -z "${DATABASE_DRIVER}" ] && DATABASE_DRIVER="mysqli"
            if [ "${DATABASE_DRIVER}" != "mysqli" ] && [ "${DATABASE_DRIVER}" != "pdo_mysql" ]; then
                echo "Invalid combination -d ${DBMS} -a ${DATABASE_DRIVER}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            [ -z "${DBMS_VERSION}" ] && DBMS_VERSION="8.0"
            if ! [[ ${DBMS_VERSION} =~ ^(8.0|8.4|9.0)$ ]]; then
                echo "Invalid combination -d ${DBMS} -i ${DBMS_VERSION}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            ;;
        postgres)
            if [ -n "${DATABASE_DRIVER}" ]; then
                echo "Invalid combination -d ${DBMS} -a ${DATABASE_DRIVER}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            [ -z "${DBMS_VERSION}" ] && DBMS_VERSION="16"
            if ! [[ ${DBMS_VERSION} =~ ^(12|13|14|15|16|17)$ ]]; then
                echo "Invalid combination -d ${DBMS} -i ${DBMS_VERSION}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            ;;
        sqlite)
            if [ -n "${DATABASE_DRIVER}" ]; then
                echo "Invalid combination -d ${DBMS} -a ${DATABASE_DRIVER}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            if [ -n "${DBMS_VERSION}" ]; then
                echo "Invalid combination -d ${DBMS} -i ${DATABASE_DRIVER}" >&2
                echo >&2
                echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
                exit 1
            fi
            ;;
        *)
            echo "Invalid option -d ${DBMS}" >&2
            echo >&2
            echo "Use \"Build/Scripts/runTests.sh -h\" to display help and valid options" >&2
            exit 1
            ;;
    esac
}

loadHelp() {
    # Load help text into $HELP
    read -r -d '' HELP <<EOF
nr-vault test runner. Execute tests and code quality tools in Docker containers.

Usage: $0 [options] [file]

Options:
    -s <...>
        Specifies which test suite to run
            - cgl: cgl test and fix all php files
            - clean: Clean temporary files
            - cleanCache: Clean cache folders
            - cleanRenderedDocumentation: Clean existing rendered documentation
            - composer: "composer" with all remaining arguments dispatched
            - composerNormalize: "composer normalize"
            - composerUpdate: "composer update"
            - composerValidate: "composer validate"
            - e2e: Playwright E2E tests (requires running TYPO3, see below)
            - functional: PHP functional tests
            - functionalParallel: PHP functional tests in parallel (faster)
            - functionalCoverage: PHP functional tests with coverage
            - lint: PHP linting
            - phpstan: PHPStan static analysis
            - phpstanBaseline: Generate PHPStan baseline
            - unit: PHP unit tests (default)
            - unitCoverage: PHP unit tests with coverage (line coverage)
            - unitCoveragePath: PHP unit tests with path + branch coverage (requires xdebug)
            - fuzz: PHP fuzz tests
            - mutation: Mutation testing with Infection
            - rector: Apply Rector rules
            - renderDocumentation: Render documentation
            - testRenderDocumentation: Test documentation rendering

    -b <docker|podman>
        Container environment:
            - docker
            - podman

        If not specified, podman will be used if available. Otherwise, docker is used.

    -a <mysqli|pdo_mysql>
        Only with -s functional
        Specifies to use another driver, following combinations are available:
            - mysql
                - mysqli (default)
                - pdo_mysql
            - mariadb
                - mysqli (default)
                - pdo_mysql

    -d <sqlite|mariadb|mysql|postgres>
        Only with -s functional
        Specifies on which DBMS tests are performed
            - sqlite: (default): use sqlite
            - mariadb: use mariadb
            - mysql: use MySQL
            - postgres: use postgres

    -i version
        Specify a specific database version
        With "-d mariadb":
            - 10.5   long-term
            - 10.6   long-term
            - 10.11  long-term (default)
            - 11.0   short-term
            - 11.4   long-term
        With "-d mysql":
            - 8.0    (default) LTS
            - 8.4    LTS
            - 9.0    Innovation
        With "-d postgres":
            - 12-17  (default: 16)

    -p <8.2|8.3|8.4|8.5>
        Specifies the PHP minor version to be used
            - 8.2: use PHP 8.2
            - 8.3: use PHP 8.3
            - 8.4: use PHP 8.4
            - 8.5: (default) use PHP 8.5

    -x
        Only with -s functional|unit
        Send information to host instance for test or system under test break points.
        This is especially useful if a local PhpStorm instance is listening on default
        xdebug port 9003. A different port can be selected with -y

    -y <port>
        Send xdebug information to a different port than default 9003 if an IDE like
        PhpStorm is not listening on default port.

    -n
        Only with -s cgl, composerNormalize, rector
        Activate dry-run that does not actively change files and only prints broken ones.

    -u
        Update existing typo3/core-testing-*:latest container images and remove dangling
        local volumes.

    -h
        Show this help.

Examples:
    # Run unit tests using the default PHP (upper supported bound)
    ./Build/Scripts/runTests.sh -s unit

    # Run unit tests with code coverage
    ./Build/Scripts/runTests.sh -s unitCoverage

    # Run functional tests using the default PHP and SQLite
    ./Build/Scripts/runTests.sh -s functional

    # Run functional tests with code coverage
    ./Build/Scripts/runTests.sh -s functionalCoverage

    # Run functional tests using PHP 8.4 and MariaDB 10.11 using pdo_mysql
    ./Build/Scripts/runTests.sh -p 8.4 -s functional -d mariadb -i 10.11 -a pdo_mysql

    # Run functional tests on postgres with xdebug
    ./Build/Scripts/runTests.sh -x -s functional -d postgres -- Tests/Functional/SomeTest.php

    # Run E2E tests (requires running TYPO3 instance)
    # Option 1: Start ddev first
    ddev start && ./Build/Scripts/runTests.sh -s e2e

    # Option 2: Provide custom TYPO3 URL
    TYPO3_BASE_URL=https://my-typo3.local ./Build/Scripts/runTests.sh -s e2e

E2E Tests:
    E2E tests require a running TYPO3 instance with the extension installed.
    The easiest way is to use ddev:
        1. ddev start
        2. ./Build/Scripts/runTests.sh -s e2e

    For CI, you can:
        - Use ddev in GitHub Actions (recommended)
        - Set TYPO3_BASE_URL to point to a test instance
EOF
}

# Test if docker exists, else exit out with error
if ! type "docker" >/dev/null 2>&1 && ! type "podman" >/dev/null 2>&1; then
    echo "This script relies on docker or podman. Please install" >&2
    exit 1
fi

# Option defaults
TEST_SUITE="unit"
DATABASE_DRIVER=""
DBMS="sqlite"
DBMS_VERSION=""
PHP_VERSION="8.5"
PHP_XDEBUG_ON=0
PHP_XDEBUG_PORT=9003
CGLCHECK_DRY_RUN=0
CI_PARAMS="${CI_PARAMS:-}"
DOCS_PARAMS="${DOCS_PARAMS:=--pull always}"
CONTAINER_BIN=""
CONTAINER_HOST="host.docker.internal"
EXTRA_TEST_OPTIONS="${EXTRA_TEST_OPTIONS:-}"

# Option parsing updates above default vars
# Reset in case getopts has been used previously in the shell
OPTIND=1
# Array for invalid options
INVALID_OPTIONS=()
# Simple option parsing based on getopts (! not getopt)
while getopts "a:b:d:i:s:p:xy:nhu" OPT; do
    case ${OPT} in
        a)
            DATABASE_DRIVER=${OPTARG}
            ;;
        s)
            TEST_SUITE=${OPTARG}
            ;;
        b)
            if ! [[ ${OPTARG} =~ ^(docker|podman)$ ]]; then
                INVALID_OPTIONS+=("${OPTARG}")
            fi
            CONTAINER_BIN=${OPTARG}
            ;;
        d)
            DBMS=${OPTARG}
            ;;
        i)
            DBMS_VERSION=${OPTARG}
            ;;
        p)
            PHP_VERSION=${OPTARG}
            if ! [[ ${PHP_VERSION} =~ ^(8.2|8.3|8.4|8.5)$ ]]; then
                INVALID_OPTIONS+=("p ${OPTARG}")
            fi
            ;;
        x)
            PHP_XDEBUG_ON=1
            ;;
        y)
            PHP_XDEBUG_PORT=${OPTARG}
            ;;
        n)
            CGLCHECK_DRY_RUN=1
            ;;
        h)
            loadHelp
            echo "${HELP}"
            exit 0
            ;;
        u)
            TEST_SUITE=update
            ;;
        \?)
            INVALID_OPTIONS+=("${OPTARG}")
            ;;
        :)
            INVALID_OPTIONS+=("${OPTARG}")
            ;;
    esac
done

# Exit on invalid options
if [ ${#INVALID_OPTIONS[@]} -ne 0 ]; then
    echo "Invalid option(s):" >&2
    for I in "${INVALID_OPTIONS[@]}"; do
        echo "-"${I} >&2
    done
    echo >&2
    echo "call \"Build/Scripts/runTests.sh -h\" to display help and valid options"
    exit 1
fi

handleDbmsOptions

COMPOSER_ROOT_VERSION="0.x-dev"
HOST_UID=$(id -u)
USERSET=""
if [ $(uname) != "Darwin" ]; then
    USERSET="--user $HOST_UID"
fi

# Go to the directory this script is located, so everything else is relative
# to this dir, no matter from where this script is called, then go up two dirs.
THIS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
cd "$THIS_SCRIPT_DIR" || exit 1
cd ../../ || exit 1
ROOT_DIR="${PWD}"

# Create .cache dir: composer need this.
mkdir -p .Build/.cache
mkdir -p .Build/web/typo3temp/var/tests

IMAGE_PREFIX="docker.io/"
# Non-CI fetches TYPO3 images (php and nodejs) from ghcr.io
TYPO3_IMAGE_PREFIX="ghcr.io/typo3/"
CONTAINER_INTERACTIVE="-it --init"

IS_CORE_CI=0
# ENV var "CI" is set by gitlab-ci/github-actions. We use it here to distinct 'local' and 'CI' environment.
# Also detect non-TTY environment (piped output, background jobs) and disable interactive mode.
if [ "${CI}" == "true" ] || ! [ -t 0 ]; then
    IS_CORE_CI=1
    IMAGE_PREFIX=""
    CONTAINER_INTERACTIVE=""
fi

# determine default container binary to use: 1. podman 2. docker
if [[ -z "${CONTAINER_BIN}" ]]; then
    if type "podman" >/dev/null 2>&1; then
        CONTAINER_BIN="podman"
    elif type "docker" >/dev/null 2>&1; then
        CONTAINER_BIN="docker"
    fi
fi

IMAGE_PHP="${TYPO3_IMAGE_PREFIX}core-testing-$(echo "php${PHP_VERSION}" | sed -e 's/\.//'):latest"
IMAGE_ALPINE="${IMAGE_PREFIX}alpine:3.20"
IMAGE_MARIADB="docker.io/mariadb:${DBMS_VERSION}"
IMAGE_MYSQL="docker.io/mysql:${DBMS_VERSION}"
IMAGE_POSTGRES="docker.io/postgres:${DBMS_VERSION}-alpine"
IMAGE_DOCS="ghcr.io/typo3-documentation/render-guides:latest"
IMAGE_MOCK_OAUTH="ghcr.io/navikt/mock-oauth2-server:3.0.1"

# Set $1 to first mass argument, this is the optional test file or test directory to execute
shift $((OPTIND - 1))

# Collision-resistant suffix: prefer CI run ID when available, fall back to PID.
# Appending nanosecond timestamp prevents collisions across concurrent runs.
SUFFIX="${GITHUB_RUN_ID:-$$}-$(date +%s%N)"
NETWORK="nr-vault-${SUFFIX}"
${CONTAINER_BIN} network create ${NETWORK} >/dev/null

if [ ${CONTAINER_BIN} = "docker" ]; then
    # docker needs the add-host for xdebug remote debugging. podman has host.container.internal built in
    CONTAINER_COMMON_PARAMS="${CONTAINER_INTERACTIVE} --rm --network ${NETWORK} --add-host "${CONTAINER_HOST}:host-gateway" ${USERSET} -v ${ROOT_DIR}:${ROOT_DIR} -w ${ROOT_DIR}"
    CONTAINER_DOCS_PARAMS="${CONTAINER_INTERACTIVE} ${DOCS_PARAMS} --rm --network ${NETWORK} --add-host "${CONTAINER_HOST}:host-gateway" ${USERSET} -v ${ROOT_DIR}:/project"
else
    # podman
    CONTAINER_HOST="host.containers.internal"
    CONTAINER_COMMON_PARAMS="${CONTAINER_INTERACTIVE} ${CI_PARAMS} --rm --network ${NETWORK} -v ${ROOT_DIR}:${ROOT_DIR} -w ${ROOT_DIR}"
    CONTAINER_DOCS_PARAMS="${CONTAINER_INTERACTIVE} ${DOCS_PARAMS} --rm --network ${NETWORK} -v ${ROOT_DIR}:/project"
fi

if [ ${PHP_XDEBUG_ON} -eq 0 ]; then
    XDEBUG_MODE="-e XDEBUG_MODE=off"
    XDEBUG_CONFIG=" "
else
    XDEBUG_MODE="-e XDEBUG_MODE=debug -e XDEBUG_TRIGGER=foo"
    XDEBUG_CONFIG="client_port=${PHP_XDEBUG_PORT} client_host=${CONTAINER_HOST}"
fi

# PHP CLI performance options: enable opcache and JIT for faster execution
PHP_OPCACHE_OPTS="-d opcache.enable_cli=1 -d opcache.jit=1255 -d opcache.jit_buffer_size=128M"

# Suite execution
case ${TEST_SUITE} in
    cgl)
        if [ "${CGLCHECK_DRY_RUN}" -eq 1 ]; then
            COMMAND="php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/php-cs-fixer fix -v --dry-run --diff"
        else
            COMMAND="php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/php-cs-fixer fix -v"
        fi
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name cgl-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} /bin/sh -c "${COMMAND}"
        SUITE_EXIT_CODE=$?
        ;;
    clean)
        cleanCacheFiles
        cleanRenderedDocumentationFiles
        ;;
    cleanCache)
        cleanCacheFiles
        ;;
    cleanRenderedDocumentation)
        cleanRenderedDocumentationFiles
        ;;
    composer)
        COMMAND=(composer "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name composer-command-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    composerNormalize)
        if [ "${CGLCHECK_DRY_RUN}" -eq 1 ]; then
            COMMAND=(composer normalize -n)
        else
            COMMAND=(composer normalize)
        fi
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name composer-command-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    composerUpdate)
        rm -rf .Build/bin/ .Build/vendor ./composer.lock
        COMMAND=(composer install --no-ansi --no-interaction --no-progress)
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name composer-install-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    composerValidate)
        COMMAND=(composer validate "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name composer-command-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    e2e)
        # E2E tests require a running TYPO3 instance
        IMAGE_PLAYWRIGHT="mcr.microsoft.com/playwright:v1.57.0-noble"

        # Detect TYPO3 URL: explicit env var > ddev > default
        if [ -n "${TYPO3_BASE_URL:-}" ]; then
            echo "Using TYPO3_BASE_URL from environment: ${TYPO3_BASE_URL}"
        elif type "ddev" >/dev/null 2>&1 && ddev describe >/dev/null 2>&1; then
            # Use v14 subdomain for TYPO3 v14 testing
            TYPO3_BASE_URL="https://v14.nr-vault.ddev.site"
            echo "Using ddev TYPO3 URL: ${TYPO3_BASE_URL}"
        else
            TYPO3_BASE_URL="https://v14.nr-vault.ddev.site"
            echo "Warning: No TYPO3 instance detected."
            echo "E2E tests require a running TYPO3 instance with the extension installed."
            echo ""
            echo "Options:"
            echo "  1. Start ddev: ddev start"
            echo "  2. Set TYPO3_BASE_URL: TYPO3_BASE_URL=https://your-typo3.local $0 -s e2e"
            echo ""
            echo "Attempting to connect to default: ${TYPO3_BASE_URL}"
        fi

        mkdir -p .Build/.cache/npm

        # Pre-create node_modules to ensure correct ownership (avoids root-owned files)
        mkdir -p node_modules

        # Check for permission issues in node_modules
        if [ -d "node_modules" ] && [ "$(find node_modules -maxdepth 1 -user root 2>/dev/null | head -1)" ]; then
            echo "Error: node_modules contains root-owned files."
            echo "Please remove node_modules and try again: sudo rm -rf node_modules"
            exit 1
        fi

        # For ddev, connect to ddev network and add host entries for routing
        DDEV_PARAMS=""
        if type "ddev" >/dev/null 2>&1 && ddev describe >/dev/null 2>&1; then
            # Get ddev-router IP address
            ROUTER_IP=$(${CONTAINER_BIN} inspect ddev-router --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)
            if [ -n "${ROUTER_IP}" ]; then
                # Connect to ddev's shared network where traefik router lives
                DDEV_PARAMS="--network ddev_default"
                # Add host entries so ddev hostnames resolve to ddev-router IP
                DDEV_PARAMS="${DDEV_PARAMS} --add-host nr-vault.ddev.site:${ROUTER_IP}"
                DDEV_PARAMS="${DDEV_PARAMS} --add-host v14.nr-vault.ddev.site:${ROUTER_IP}"
                DDEV_PARAMS="${DDEV_PARAMS} --add-host docs.nr-vault.ddev.site:${ROUTER_IP}"
                DDEV_PARAMS="${DDEV_PARAMS} --add-host mock-oauth.nr-vault.ddev.site:${ROUTER_IP}"
                echo "Connecting to ddev network (router IP: ${ROUTER_IP})"
            fi
        fi

        COMMAND="npm ci && npx playwright test $*"
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} ${DDEV_PARAMS} --name e2e-${SUFFIX} \
            -e TYPO3_BASE_URL="${TYPO3_BASE_URL}" \
            -e CI="${CI:-}" \
            -e npm_config_cache="${ROOT_DIR}/.Build/.cache/npm" \
            ${IMAGE_PLAYWRIGHT} /bin/bash -c "${COMMAND}"
        SUITE_EXIT_CODE=$?
        ;;
    functional)
        CONTAINER_PARAMS=""
        COMMAND=(php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/phpunit -c Build/FunctionalTests.xml --exclude-group not-${DBMS} ${EXTRA_TEST_OPTIONS} "$@")

        # Start mock OAuth server for OAuth integration tests
        MOCK_OAUTH_CONTAINER="mock-oauth-${SUFFIX}"
        MOCK_OAUTH_URL="http://${MOCK_OAUTH_CONTAINER}:8080"
        echo "Starting mock OAuth server..."
        ${CONTAINER_BIN} run --rm ${CI_PARAMS} --name ${MOCK_OAUTH_CONTAINER} --network ${NETWORK} -d \
            -e SERVER_PORT=8080 \
            -e JSON_CONFIG_PATH=/config/config.json \
            -v "${ROOT_DIR}/.ddev/mock-oauth:/config:ro" \
            ${IMAGE_MOCK_OAUTH} >/dev/null
        waitFor ${MOCK_OAUTH_CONTAINER} 8080

        # Common OAuth params for all database backends
        OAUTH_PARAMS="-e MOCK_OAUTH_URL=${MOCK_OAUTH_URL}"

        case ${DBMS} in
            mariadb)
                echo "Using driver: ${DATABASE_DRIVER}"
                ${CONTAINER_BIN} run --rm ${CI_PARAMS} --name mariadb-func-${SUFFIX} --network ${NETWORK} -d -e MYSQL_ROOT_PASSWORD=funcp --tmpfs /var/lib/mysql/:rw,noexec,nosuid ${IMAGE_MARIADB} >/dev/null
                waitFor mariadb-func-${SUFFIX} 3306
                CONTAINERPARAMS="-e typo3DatabaseDriver=${DATABASE_DRIVER} -e typo3DatabaseName=func_test -e typo3DatabaseUsername=root -e typo3DatabaseHost=mariadb-func-${SUFFIX} -e typo3DatabasePassword=funcp"
                ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name functional-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${CONTAINERPARAMS} ${OAUTH_PARAMS} ${IMAGE_PHP} "${COMMAND[@]}"
                SUITE_EXIT_CODE=$?
                ;;
            mysql)
                echo "Using driver: ${DATABASE_DRIVER}"
                ${CONTAINER_BIN} run --rm ${CI_PARAMS} --name mysql-func-${SUFFIX} --network ${NETWORK} -d -e MYSQL_ROOT_PASSWORD=funcp --tmpfs /var/lib/mysql/:rw,noexec,nosuid ${IMAGE_MYSQL} >/dev/null
                waitFor mysql-func-${SUFFIX} 3306
                CONTAINERPARAMS="-e typo3DatabaseDriver=${DATABASE_DRIVER} -e typo3DatabaseName=func_test -e typo3DatabaseUsername=root -e typo3DatabaseHost=mysql-func-${SUFFIX} -e typo3DatabasePassword=funcp"
                ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name functional-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${CONTAINERPARAMS} ${OAUTH_PARAMS} ${IMAGE_PHP} "${COMMAND[@]}"
                SUITE_EXIT_CODE=$?
                ;;
            postgres)
                ${CONTAINER_BIN} run --rm ${CI_PARAMS} --name postgres-func-${SUFFIX} --network ${NETWORK} -d -e POSTGRES_PASSWORD=funcp -e POSTGRES_USER=funcu --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid ${IMAGE_POSTGRES} >/dev/null
                waitFor postgres-func-${SUFFIX} 5432
                CONTAINERPARAMS="-e typo3DatabaseDriver=pdo_pgsql -e typo3DatabaseName=bamboo -e typo3DatabaseUsername=funcu -e typo3DatabaseHost=postgres-func-${SUFFIX} -e typo3DatabasePassword=funcp"
                ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name functional-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${CONTAINERPARAMS} ${OAUTH_PARAMS} ${IMAGE_PHP} "${COMMAND[@]}"
                SUITE_EXIT_CODE=$?
                ;;
            sqlite)
                # create sqlite tmpfs mount typo3temp/var/tests/functional-sqlite-dbs/ to avoid permission issues
                mkdir -p "${ROOT_DIR}/.Build/web/typo3temp/var/tests/functional-sqlite-dbs/"
                CONTAINERPARAMS="-e typo3DatabaseDriver=pdo_sqlite --tmpfs ${ROOT_DIR}/.Build/web/typo3temp/var/tests/functional-sqlite-dbs/:rw,noexec,nosuid"
                ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name functional-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${CONTAINERPARAMS} ${OAUTH_PARAMS} ${IMAGE_PHP} "${COMMAND[@]}"
                SUITE_EXIT_CODE=$?
                ;;
        esac
        ;;
    functionalCoverage)
        mkdir -p .Build/coverage
        # Coverage requires xdebug, no JIT. pcov.enabled=0 forces xdebug driver if both are installed
        COMMAND=(php -d opcache.enable_cli=1 -d pcov.enabled=0 .Build/bin/phpunit -c Build/FunctionalTests.xml --coverage-clover=.Build/coverage/functional.xml --coverage-html=.Build/coverage/html-functional --coverage-text ${EXTRA_TEST_OPTIONS} "$@")

        # Start mock OAuth server for OAuth integration tests
        MOCK_OAUTH_CONTAINER="mock-oauth-${SUFFIX}"
        MOCK_OAUTH_URL="http://${MOCK_OAUTH_CONTAINER}:8080"
        echo "Starting mock OAuth server..."
        ${CONTAINER_BIN} run --rm ${CI_PARAMS} --name ${MOCK_OAUTH_CONTAINER} --network ${NETWORK} -d \
            -e SERVER_PORT=8080 \
            -e JSON_CONFIG_PATH=/config/config.json \
            -v "${ROOT_DIR}/.ddev/mock-oauth:/config:ro" \
            ${IMAGE_MOCK_OAUTH} >/dev/null
        waitFor ${MOCK_OAUTH_CONTAINER} 8080

        # Functional coverage only runs with SQLite for simplicity
        mkdir -p "${ROOT_DIR}/.Build/web/typo3temp/var/tests/functional-sqlite-dbs/"
        CONTAINERPARAMS="-e typo3DatabaseDriver=pdo_sqlite --tmpfs ${ROOT_DIR}/.Build/web/typo3temp/var/tests/functional-sqlite-dbs/:rw,noexec,nosuid"
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name functional-coverage-${SUFFIX} -e XDEBUG_MODE=coverage ${CONTAINERPARAMS} -e MOCK_OAUTH_URL=${MOCK_OAUTH_URL} ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    functionalParallel)
        # Parallel functional tests - runs test files concurrently using GNU parallel
        # Each test class gets its own isolated SQLite database, so parallelization is safe

        # Start mock OAuth server for OAuth integration tests
        MOCK_OAUTH_CONTAINER="mock-oauth-${SUFFIX}"
        MOCK_OAUTH_URL="http://${MOCK_OAUTH_CONTAINER}:8080"
        echo "Starting mock OAuth server..."
        ${CONTAINER_BIN} run --rm ${CI_PARAMS} --name ${MOCK_OAUTH_CONTAINER} --network ${NETWORK} -d \
            -e SERVER_PORT=8080 \
            -e JSON_CONFIG_PATH=/config/config.json \
            -v "${ROOT_DIR}/.ddev/mock-oauth:/config:ro" \
            ${IMAGE_MOCK_OAUTH} >/dev/null
        waitFor ${MOCK_OAUTH_CONTAINER} 8080

        mkdir -p "${ROOT_DIR}/.Build/web/typo3temp/var/tests/functional-sqlite-dbs/"
        # Run functional tests in parallel using xargs
        # Each test file runs in its own PHPUnit process with isolated SQLite DB
        # CI: fixed 4 jobs for predictable resource usage on shared runners
        # Local: half of available CPUs (similar to Playwright's default)
        if [ "${CI}" == "true" ]; then
            PARALLEL_JOBS=4
        else
            PARALLEL_JOBS="\$(((\$(nproc) + 1) / 2))"
        fi
        COMMAND="find Tests/Functional -name '*Test.php' | xargs -P${PARALLEL_JOBS} -I{} php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/phpunit -c Build/FunctionalTests.xml {}"
        CONTAINERPARAMS="-e typo3DatabaseDriver=pdo_sqlite --tmpfs ${ROOT_DIR}/.Build/web/typo3temp/var/tests/functional-sqlite-dbs/:rw,noexec,nosuid"
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name functional-parallel-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${CONTAINERPARAMS} -e MOCK_OAUTH_URL=${MOCK_OAUTH_URL} ${IMAGE_PHP} /bin/sh -c "${COMMAND}"
        SUITE_EXIT_CODE=$?
        ;;
    lint)
        # -prune rather than a `! -path` filter: the old exclusion was written
        # `! -path "./.Build/\*"`, and the escaped star survives the double
        # quotes, so find looked for a literal `*` and never matched. .Build was
        # linted too and the suite died on class-alias-loader's
        # alias-loader-include.tmpl.php, a template that is deliberately not
        # valid PHP. Pruning also skips walking the vendor tree.
        COMMAND="find . -path ./.Build -prune -o -name '*.php' -print0 | xargs -0 -n1 -P\$(nproc) php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off -l >/dev/null"
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name lint-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} /bin/sh -c "${COMMAND}"
        SUITE_EXIT_CODE=$?
        ;;
    phpstan)
        COMMAND="php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/phpstan analyse"
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name phpstan-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} /bin/sh -c "${COMMAND}"
        SUITE_EXIT_CODE=$?
        ;;
    phpstanBaseline)
        COMMAND="php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/phpstan analyse --generate-baseline -v"
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name phpstan-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} /bin/sh -c "${COMMAND}"
        SUITE_EXIT_CODE=$?
        ;;
    rector)
        if [ "${CGLCHECK_DRY_RUN}" -eq 1 ]; then
            COMMAND=(php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/rector -n --clear-cache "$@")
        else
            COMMAND=(php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/rector --clear-cache "$@")
        fi
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name rector-${SUFFIX} -e COMPOSER_CACHE_DIR=.Build/.cache/composer -e COMPOSER_ROOT_VERSION=${COMPOSER_ROOT_VERSION} ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    renderDocumentation)
        COMMAND=(--config=Documentation "$@")
        mkdir -p Documentation-GENERATED-temp
        ${CONTAINER_BIN} run ${CONTAINER_INTERACTIVE} ${CONTAINER_DOCS_PARAMS} --name render-documentation-${SUFFIX} ${IMAGE_DOCS} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    testRenderDocumentation)
        COMMAND=(--config=Documentation --no-progress --fail-on-log "$@")
        mkdir -p Documentation-GENERATED-temp
        ${CONTAINER_BIN} run ${CONTAINER_INTERACTIVE} ${CONTAINER_DOCS_PARAMS} --name render-documentation-test-${SUFFIX} ${IMAGE_DOCS} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    unit)
        COMMAND=(php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/phpunit -c Build/phpunit.xml --testsuite Unit ${EXTRA_TEST_OPTIONS} "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name unit-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    unitCoverage)
        mkdir -p .Build/coverage
        # Coverage requires xdebug, no JIT. pcov.enabled=0 forces xdebug driver if both are installed in the container
        COMMAND=(php -d opcache.enable_cli=1 -d pcov.enabled=0 .Build/bin/phpunit -c Build/phpunit.xml --testsuite Unit --coverage-clover=.Build/coverage/unit.xml --coverage-html=.Build/coverage/html-unit --coverage-text ${EXTRA_TEST_OPTIONS} "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name unit-coverage-${SUFFIX} -e XDEBUG_MODE=coverage ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    unitCoveragePath)
        mkdir -p .Build/coverage
        # Path + branch coverage requires xdebug (PCOV does not support these metrics)
        COMMAND=(php -d opcache.enable_cli=1 -d pcov.enabled=0 .Build/bin/phpunit -c Build/phpunit.xml --testsuite Unit --path-coverage --coverage-clover=.Build/coverage/unit-path.xml --coverage-html=.Build/coverage/html-unit-path --coverage-text ${EXTRA_TEST_OPTIONS} "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name unit-coverage-path-${SUFFIX} -e XDEBUG_MODE=coverage ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    fuzz)
        COMMAND=(php ${PHP_OPCACHE_OPTS} -dxdebug.mode=off .Build/bin/phpunit -c Build/phpunit.xml --testsuite Fuzz ${EXTRA_TEST_OPTIONS} "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name fuzz-${SUFFIX} ${XDEBUG_MODE} -e XDEBUG_CONFIG="${XDEBUG_CONFIG}" ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    mutation)
        # Mutation testing requires coverage, no JIT
        COMMAND=(php -d opcache.enable_cli=1 .Build/bin/infection --configuration=infection.json5 --threads=4 "$@")
        ${CONTAINER_BIN} run ${CONTAINER_COMMON_PARAMS} --name mutation-${SUFFIX} -e XDEBUG_MODE=coverage ${IMAGE_PHP} "${COMMAND[@]}"
        SUITE_EXIT_CODE=$?
        ;;
    update)
        # pull typo3/core-testing-* versions of those ones that exist locally
        echo "> pull ${TYPO3_IMAGE_PREFIX}core-testing-* versions of those ones that exist locally"
        ${CONTAINER_BIN} images "${TYPO3_IMAGE_PREFIX}core-testing-*" --format "{{.Repository}}:{{.Tag}}" | xargs -I {} ${CONTAINER_BIN} pull {}
        echo ""
        # remove "dangling" typo3/core-testing-* images (those tagged as <none>)
        echo "> remove \"dangling\" ${TYPO3_IMAGE_PREFIX}/core-testing-* images (those tagged as <none>)"
        ${CONTAINER_BIN} images --filter "reference=${TYPO3_IMAGE_PREFIX}/core-testing-*" --filter "dangling=true" --format "{{.ID}}" | xargs -I {} ${CONTAINER_BIN} rmi -f {}
        echo ""
        ;;
    *)
        loadHelp
        echo "Invalid -s option argument ${TEST_SUITE}" >&2
        echo >&2
        echo "${HELP}" >&2
        exit 1
        ;;
esac

cleanUp

# Print summary
echo "" >&2
echo "###########################################################################" >&2
echo "Result of ${TEST_SUITE}" >&2
echo "Container runtime: ${CONTAINER_BIN}" >&2
if [[ ${IS_CORE_CI} -eq 1 ]]; then
    echo "Environment: CI" >&2
else
    echo "Environment: local" >&2
fi
echo "PHP: ${PHP_VERSION}" >&2
if [[ ${TEST_SUITE} =~ ^functional$ ]]; then
    case "${DBMS}" in
        mariadb|mysql)
            echo "DBMS: ${DBMS}  version ${DBMS_VERSION}  driver ${DATABASE_DRIVER}" >&2
            ;;
        postgres)
            echo "DBMS: ${DBMS}  version ${DBMS_VERSION}  driver pdo_pgsql" >&2
            ;;
        sqlite)
            echo "DBMS: ${DBMS}  driver pdo_sqlite" >&2
            ;;
    esac
fi
if [[ ${SUITE_EXIT_CODE} -eq 0 ]]; then
    echo "SUCCESS" >&2
else
    echo "FAILURE" >&2
fi
echo "###########################################################################" >&2
echo "" >&2

# Exit with code of test suite - This script return non-zero if the executed test failed.
exit $SUITE_EXIT_CODE
