ARG BASE_IMAGE
FROM $BASE_IMAGE

# Upgrade PHP to the latest patch version (newer than the DDEV base image ships).
# During an image build there is no service manager, so the php*-fpm postinst's
# attempt to (re)start the FPM service makes dpkg fail (exit 100) and aborts the
# whole dist-upgrade. A policy-rc.d returning 101 tells the package scripts to
# skip service (re)starts during the build; DDEV starts php-fpm itself at runtime.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d && \
    DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y \
        -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" && \
    rm -f /usr/sbin/policy-rc.d && \
    rm -rf /var/lib/apt/lists/*

ENV EXTENSION_KEY "nr_vault"
ENV DDEV_SITENAME "nr-vault"
ENV GITHUB_URL "https://github.com/netresearch/t3x-nr-vault"

# Remove default Apache index.html and create PHP-based landing page with Netresearch branding
RUN rm -f /var/www/html/index.html
RUN cat > /var/www/html/index.php << 'PHPEOF'
<?php
$gitInfoFile = '/var/www/html/.git-info.json';
$gitInfo = file_exists($gitInfoFile) ? json_decode(file_get_contents($gitInfoFile), true) : [];
$gitBranch = $gitInfo['branch'] ?? 'unknown';
$gitCommit = $gitInfo['commit'] ?? 'unknown';
$prNumber = isset($gitInfo['pr']) && $gitInfo['pr'] !== 'unknown' && $gitInfo['pr'] !== 'none' ? $gitInfo['pr'] : null;
$githubUrl = 'https://github.com/netresearch/t3x-nr-vault';
$branchUrl = $githubUrl && $gitBranch !== 'unknown' ? $githubUrl . '/tree/' . urlencode($gitBranch) : null;
$prUrl = $githubUrl && $prNumber ? $githubUrl . '/pull/' . $prNumber : null;
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EXT:nr_vault - Development Environment</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Raleway:wght@400;600;700&family=Open+Sans:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #2F99A4;
            --primary-dark: #257880;
            --accent: #FF4D00;
            --accent-dark: #CC3D00;
            --text: #585961;
            --grey: #CCCDCC;
            --bg: #F5F5F5;
            --white: #FFFFFF;
            --spacing-sm: 12px;
            --spacing-md: 16px;
            --spacing-lg: 24px;
            --spacing-xl: 32px;
            --spacing-xxl: 48px;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Open Sans', sans-serif;
            font-size: 16px;
            line-height: 1.6;
            color: var(--text);
            background: var(--bg);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        h1, h2, h3, h4 { font-family: 'Raleway', sans-serif; font-weight: 600; }
        a { color: var(--primary); text-decoration: none; transition: color 0.3s; }
        a:hover { color: var(--primary-dark); }

        /* Header */
        .header {
            background: var(--white);
            border-bottom: 3px solid var(--primary);
            padding: var(--spacing-md) var(--spacing-lg);
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .header-left { display: flex; align-items: center; gap: var(--spacing-md); }
        .logo { width: 48px; height: 48px; }
        .header h1 { font-size: 1.5rem; color: var(--primary); margin: 0; }
        .git-info {
            font-size: 0.85rem;
            color: var(--grey);
            padding: 6px 12px;
            background: var(--bg);
            border-radius: 4px;
        }
        .git-info a { color: var(--text); font-weight: 600; }

        /* Main */
        main {
            flex: 1;
            max-width: 1200px;
            margin: 0 auto;
            padding: var(--spacing-xxl) var(--spacing-lg);
            width: 100%;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: var(--spacing-lg);
        }
        .card {
            background: var(--white);
            border-radius: 8px;
            padding: var(--spacing-lg);
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border-left: 4px solid var(--primary);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .card:hover { transform: translateY(-4px); box-shadow: 0 8px 24px rgba(0,0,0,0.12); }
        .card h3 { color: var(--primary); margin-bottom: var(--spacing-sm); font-size: 1.25rem; }
        .card p { margin-bottom: var(--spacing-md); }
        .card code {
            background: var(--bg);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
            font-family: monospace;
        }

        /* Buttons */
        .btn {
            display: inline-block;
            font-family: 'Raleway', sans-serif;
            font-weight: 600;
            padding: 12px 24px;
            border-radius: 4px;
            text-decoration: none;
            transition: all 0.3s;
            cursor: pointer;
            border: none;
        }
        .btn-primary { background: var(--primary); color: var(--white); }
        .btn-primary:hover { background: var(--primary-dark); color: var(--white); transform: translateY(-2px); }
        .btn-accent { background: var(--accent); color: var(--white); }
        .btn-accent:hover { background: var(--accent-dark); color: var(--white); transform: translateY(-2px); }
        .links { display: flex; gap: var(--spacing-sm); flex-wrap: wrap; margin-top: var(--spacing-md); }

        /* Info sections */
        .info {
            background: var(--white);
            border-radius: 8px;
            padding: var(--spacing-lg);
            margin-top: var(--spacing-lg);
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        .info h3 { color: var(--text); margin-bottom: var(--spacing-md); }
        .info table { width: 100%; border-collapse: collapse; }
        .info td { padding: 8px 0; border-bottom: 1px solid var(--bg); }
        .info td:first-child { font-weight: 600; width: 180px; color: var(--text); }
        .info tr:last-child td { border-bottom: none; }

        /* Footer */
        .footer {
            background: var(--text);
            color: var(--white);
            padding: var(--spacing-lg);
            text-align: center;
            margin-top: auto;
        }
        .footer a { color: var(--primary); font-weight: 600; }
        .footer a:hover { color: #3eb8c5; }

        @media (max-width: 768px) {
            .header { flex-direction: column; gap: var(--spacing-sm); text-align: center; }
            .header-left { flex-direction: column; }
            .git-info { margin-top: var(--spacing-sm); }
        }
    </style>
</head>
<body>
    <header class="header">
        <div class="header-left">
            <svg class="logo" viewBox="-75 -75 440 440" xmlns="http://www.w3.org/2000/svg">
                <title>Netresearch DTT GmbH</title>
                <g>
                    <path fill="#2999a4" d="M209.6,0V31.62h32.77a26.38,26.38,0,0,1,26.44,26.43V242a26.38,26.38,0,0,1-26.44,26.44H209.6V300h47.93a42.77,42.77,0,0,0,42.86-42.86V42.89A42.76,42.76,0,0,0,257.53,0ZM43.25,0A42.76,42.76,0,0,0,.39,42.89V257.18A42.76,42.76,0,0,0,43.25,300H91.18V268.46H58.4A26.38,26.38,0,0,1,32,242v-184A26.37,26.37,0,0,1,58.4,31.62H91.18V0Z" transform="translate(-0.39 -0.04)"/>
                    <path fill="#595a62" d="M221.44,120.41c0-34.48-13.94-57.82-48.93-57.82-26.62,0-48.54,7.74-64.17,26.56l-.7-22.06-28.31.06V232.94h31.59V124.69c7.14-18.38,32.14-34.8,53-34.5,27.38.4,25.2,26.24,26,45.81v96.94h31.58" transform="translate(-0.39 -0.04)"/>
                </g>
            </svg>
            <h1>EXT:nr_vault Development</h1>
        </div>
        <?php if ($gitBranch !== 'unknown' || $prNumber): ?>
        <div class="git-info">
            <?php if ($branchUrl): ?>
                <a href="<?= htmlspecialchars($branchUrl) ?>" target="_blank"><?= htmlspecialchars($gitBranch) ?></a>
                <?php if ($gitCommit !== 'unknown'): ?> @ <?= htmlspecialchars($gitCommit) ?><?php endif; ?>
            <?php endif; ?>
            <?php if ($prUrl): ?> | <a href="<?= htmlspecialchars($prUrl) ?>" target="_blank">PR #<?= htmlspecialchars($prNumber) ?></a><?php endif; ?>
        </div>
        <?php endif; ?>
    </header>

    <main>
        <div class="cards">
            <div class="card">
                <h3>TYPO3 v14 Backend</h3>
                <p>Access the TYPO3 backend to test the nr_vault extension.</p>
                <div class="links">
                    <a href="https://v14.nr-vault.ddev.site/" class="btn btn-primary">Frontend</a>
                    <a href="https://v14.nr-vault.ddev.site/typo3/" class="btn btn-primary">Backend</a>
                </div>
            </div>

            <div class="card">
                <h3>Documentation</h3>
                <p>Extension documentation rendered from <code>Documentation/</code>.</p>
                <div class="links">
                    <a href="https://docs.nr-vault.ddev.site/" class="btn btn-accent">View Docs</a>
                </div>
            </div>

            <div class="card">
                <h3>GitHub Repository</h3>
                <p>Source code, issues, and pull requests.</p>
                <div class="links">
                    <a href="https://github.com/netresearch/t3x-nr-vault" class="btn btn-primary">View on GitHub</a>
                </div>
            </div>
        </div>

        <div class="info">
            <h3>Credentials</h3>
            <table>
                <tr><td>Username</td><td><code>admin</code></td></tr>
                <tr><td>Password</td><td><code>Joh316!!</code></td></tr>
            </table>
        </div>

        <div class="info">
            <h3>Quick Reference</h3>
            <table>
                <tr><td>Extension Key</td><td><code>nr_vault</code></td></tr>
                <tr><td>Package</td><td><code>netresearch/nr-vault</code></td></tr>
                <tr><td>PHP Version</td><td>8.5+</td></tr>
                <tr><td>TYPO3 Version</td><td>14.x</td></tr>
            </table>
        </div>

        <div class="info">
            <h3>Make Commands</h3>
            <table>
                <tr><td><code>make up</code></td><td>Start environment, install TYPO3, render docs</td></tr>
                <tr><td><code>make test</code></td><td>Run all tests</td></tr>
                <tr><td><code>make ci</code></td><td>Run all CI checks</td></tr>
                <tr><td><code>make docs</code></td><td>Render documentation</td></tr>
                <tr><td><code>make shell</code></td><td>Open shell in container</td></tr>
            </table>
        </div>
    </main>

    <footer class="footer">
        <a href="https://www.netresearch.de/" target="_blank">Netresearch DTT GmbH</a>
    </footer>
</body>
</html>
PHPEOF

RUN mkdir -p /var/www/html/v14/public/typo3
RUN echo "<h1>Run this first</h1><code>ddev install-v14</code>" > /var/www/html/v14/public/index.html
RUN echo "<h1>Run this first</h1><code>ddev install-v14</code>" > /var/www/html/v14/public/typo3/index.html

ARG uid
ARG gid
RUN chown -R $uid:$gid /var/www/html
