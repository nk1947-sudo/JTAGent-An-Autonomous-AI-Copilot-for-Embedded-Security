// Runtime validation derived from the authoritative backend schema. contracts/openapi.json is generated
// from the Pydantic models (scripts/generate_contracts.py); scripts/gen-validators.mjs turns it into
// standalone validators at build time. They are pre-compiled because the page's Content Security Policy
// forbids eval, and there is deliberately no hand-written schema that could drift from the backend.
import type { components } from './api';
import { KNOWN_OPERATIONS as generatedOperations, validators } from './generated/validators.js';

export type Schemas = components['schemas'];
export type SchemaName = keyof Schemas;
export type Checked<T> = { ok: true; value: T } | { ok: false; errors: string[] };
type Failure = { instancePath: string; message?: string; keyword?: string };

/** Debugger operations this build knows, taken from the schema rather than restated. */
export const KNOWN_OPERATIONS: string[] = generatedOperations;

function describe(errors: Failure[]): string[] {
  return errors.slice(0, 6).map(e => `${e.instancePath || '/'} ${e.message ?? 'is invalid'}`);
}

export function validate<K extends SchemaName>(name: K, data: unknown): Checked<Schemas[K]> {
  const check = validators[String(name)];
  if (!check) return { ok: false, errors: [`no compiled validator for ${String(name)}`] };
  return check(data) ? { ok: true, value: data as Schemas[K] } : { ok: false, errors: describe((check.errors ?? []) as Failure[]) };
}

/**
 * Advice may carry an action type newer than this build. That single violation is tolerated so the
 * rest of the advice still renders; the action is shown as unrecognized and never as executable.
 * Any other violation rejects the whole response.
 */
export function validateAdvice(data: unknown): Checked<Schemas['DebuggerAdvice']> {
  const strict = validate('DebuggerAdvice', data);
  if (strict.ok) return strict;
  const errors = (validators.DebuggerAdvice.errors ?? []) as Failure[];
  const onlyUnknownOperations = errors.every(e => e.keyword === 'enum' && /^\/actions\/\d+\/operation$/.test(e.instancePath));
  return onlyUnknownOperations && Array.isArray((data as { actions?: unknown }).actions)
    ? { ok: true, value: data as Schemas['DebuggerAdvice'] }
    : strict;
}

export function validateList<K extends SchemaName>(name: K, data: unknown): { valid: Schemas[K][]; rejected: string[] } {
  if (!Array.isArray(data)) return { valid: [], rejected: ['response is not a list'] };
  const valid: Schemas[K][] = [], rejected: string[] = [];
  data.forEach((item, index) => {
    const checked = validate(name, item);
    if (checked.ok) valid.push(checked.value);
    else rejected.push(`#${index}: ${checked.errors[0]}`);
  });
  return { valid, rejected };
}
