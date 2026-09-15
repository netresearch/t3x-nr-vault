import { execFileSync } from 'node:child_process';

/**
 * Direct SQL access to the TYPO3 database the suite runs against, for specs
 * that must change state the UI cannot reach (e.g. tampering with an audit row).
 *
 * The command is taken from `E2E_DB_EXEC` when set — whitespace-separated argv
 * of a client that reads one statement from stdin and prints tab-separated rows
 * without headers, e.g. `mysql -h127.0.0.1 -uroot -N -B typo3` with the password
 * in `MYSQL_PWD`. Without it, the DDEV database is used via `ddev mysql -N -B`,
 * which resolves the project from the working directory (the repo root).
 *
 * Arguments go to execFileSync as an argv array (no shell) and the SQL is fed
 * via stdin, so statement text never reaches a shell parser.
 */
function dbCommand(): { command: string; args: string[]; configured: boolean } {
  const configured = (process.env.E2E_DB_EXEC ?? '').trim();
  if (configured !== '') {
    const [command, ...args] = configured.split(/\s+/);
    return { command, args, configured: true };
  }
  return { command: 'ddev', args: ['mysql', '-N', '-B'], configured: false };
}

/**
 * Whether a database client was configured explicitly. When it was, a failing
 * client is a broken environment and must fail the spec instead of skipping it.
 */
export function isDbExecConfigured(): boolean {
  return dbCommand().configured;
}

/**
 * Run a single SQL statement. Returns the trimmed stdout, or null when the
 * client could not be run or the statement failed.
 */
export function runSql(sql: string): string | null {
  const { command, args } = dbCommand();
  try {
    const result = execFileSync(command, args, {
      cwd: process.cwd(),
      encoding: 'utf8',
      input: sql,
      timeout: 15000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return result.trim();
  } catch {
    return null;
  }
}
