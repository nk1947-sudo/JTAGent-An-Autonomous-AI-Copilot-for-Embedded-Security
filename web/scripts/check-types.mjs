// Fails when src/api.d.ts differs from what contracts/openapi.json generates (contract drift).
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
const generated = execFileSync(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['openapi-typescript', '../contracts/openapi.json'], { encoding: 'utf8', shell: process.platform === 'win32' });
const norm = s => s.replaceAll('\r\n', '\n').replace(/^\/\*\*[\s\S]*?\*\/\n/, '').trim();
const committed = readFileSync(new URL('../src/api.d.ts', import.meta.url), 'utf8');
if (norm(generated) !== norm(committed)) {
  console.error('src/api.d.ts is out of date with contracts/openapi.json. Run: npm run types');
  process.exit(1);
}
console.log('api.d.ts matches contracts/openapi.json');
