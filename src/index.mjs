// polycheck programmatic API — one call that scans a repo and returns the full
// analysis bundle. Pure and deterministic: same repo + same labels ⇒ same
// bundle (no clock, no network). Tests and the CLI both go through here.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { scanRepo } from './scan.mjs';
import { loadLabels, DEFAULT_LABELS } from './label.mjs';
import { buildModel } from './model.mjs';
import { modelCheck } from './check.mjs';
import { tidyPolicy } from './tidy.mjs';
import { loadMandate, checkMandate } from './mandate.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_REGIONS = join(HERE, '..', 'data', 'regions.json');
const VERSION = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8')).version;

export { scanRepo, loadLabels, buildModel, modelCheck, tidyPolicy, loadMandate, checkMandate, DEFAULT_LABELS };

export function analyze(root, { labelsPath = DEFAULT_LABELS, regionsPath = DEFAULT_REGIONS, assumeDefaults = true, mandatePath = null } = {}) {
  const scan = scanRepo(root);
  const labels = loadLabels(labelsPath);
  const regions = JSON.parse(readFileSync(regionsPath, 'utf8'));
  const model = buildModel(scan, labels, regions, { assumeDefaults });
  const check = modelCheck(model);
  // The mandate is a SECOND, narrower policy surface, and it is opt-in: with no
  // --mandate the bundle carries null and nothing downstream changes. That is
  // deliberate — a repo that does not use this feature must get a byte-identical
  // report to the one it got before the feature existed.
  const mandate = mandatePath ? checkMandate({ scan, model, check }, loadMandate(mandatePath)) : null;
  // assumeDefaults is carried on the bundle so a re-analysis (tidy's edit proof)
  // reproduces the same modeling choices it is comparing against.
  return { version: VERSION, scan, labels, model, check, mandate, assumeDefaults };
}
