// Repo config is attacker-controlled when scanning directories the user never vetted.
// core.fsmonitor runs on index reads, so every git invocation in enview goes through gitSync.
import { execFileSync } from 'node:child_process';

// log.showSignature is defense-in-depth against gpg.program; it did not fire with our current args.
export const GIT_HARDENING = ['-c', 'core.fsmonitor=false', '-c', 'log.showSignature=false'];

export function gitSync(args, options) {
  return execFileSync('git', [...GIT_HARDENING, ...args], options);
}
