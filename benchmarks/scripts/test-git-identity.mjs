import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function cleanGitIdentityEnvironment(t, commit = 'f'.repeat(40)) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bonvoyage-test-git-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const executable = path.join(directory, 'git');
  fs.writeFileSync(executable, `#!/bin/sh
set -eu
if [ "\${1:-}" = "-C" ]; then
  shift 2
fi
case "\${1:-}" in
  rev-parse)
    [ "\${2:-}" = "HEAD" ] || exit 2
    printf '%s\\n' '${commit}'
    ;;
  status)
    ;;
  merge-base)
    exit 0
    ;;
  diff)
    ;;
  *)
    printf 'unexpected test git command: %s\\n' "$*" >&2
    exit 2
    ;;
esac
`, {mode: 0o755});
  return {...process.env, PATH: `${directory}:${process.env.PATH}`};
}
