import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MARKER = 'JTAGENT_TEST_STACK ';

/** Starts the isolated stack and returns the teardown Playwright runs afterwards (also on failure). */
export default async function globalSetup() {
  const child = spawn('uv', ['run', '--project', root, 'python', 'scripts/test_stack.py'], {
    cwd: root,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  let output = '';
  child.stderr.on('data', chunk => { output += chunk; });
  const info = await new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('test stack did not start in 90s\n' + output)), 90_000);
    let buffer = '';
    child.stdout.on('data', chunk => {
      buffer += chunk;
      const line = buffer.split('\n').find(l => l.startsWith(MARKER));
      if (line) { clearTimeout(timer); resolve(line.slice(MARKER.length)); }
    });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`test stack exited early (${code})\n${output}`)); });
  });
  process.env.E2E_STACK = info;
  return async () => {
    // Closing stdin is the launcher's shutdown signal; it terminates only the services it started.
    child.stdin.end();
    await new Promise<void>(resolve => {
      const force = setTimeout(() => { child.kill(); resolve(); }, 20_000);
      child.on('exit', () => { clearTimeout(force); resolve(); });
      if (child.exitCode !== null) { clearTimeout(force); resolve(); }
    });
  };
}
