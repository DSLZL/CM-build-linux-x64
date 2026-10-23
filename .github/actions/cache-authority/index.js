const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { appendFileSync } = require('node:fs');
const path = require('node:path');

function verifyMode(actual, expected) {
  assert.ok(['read', 'write'].includes(actual), 'Runner did not grant a supported cache mode');
  assert.equal(actual, expected, 'Runner cache authority differs from trusted preflight');
}

assert.throws(() => verifyMode(undefined, 'write'));
assert.throws(() => verifyMode('write', 'read'));
assert.throws(() => verifyMode('none', 'none'));
const mode = process.env.ACTIONS_CACHE_MODE;
verifyMode(mode, process.env.CM_CACHE_MODE);
execFileSync('python3', ['-B', path.join(__dirname, '../../scripts/worker_policy.py'), 'verify-checkout'],
  { stdio: 'inherit' });
// The runner injects this value into JavaScript actions, not shell run steps.
appendFileSync(process.env.GITHUB_ENV, `ACTIONS_CACHE_MODE=${mode}\n`);
