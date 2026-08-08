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

const HERE = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_REGIONS = join(HERE, '..', 'data', 'regions.json');
const VERSION = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8')).version;

export { scanRepo, loadLabels, buildModel, modelCheck, DEFAULT_LABELS };

export function analyze(root, { labelsPath = DEFAULT_LABELS, regionsPath = DEFAULT_REGIONS, assumeDefaults = true } = {}) {
  const scan = scanRepo(root);
  const labels = loadLabels(labelsPath);
  const regions = JSON.parse(readFileSync(regionsPath, 'utf8'));
  const model = buildModel(scan, labels, regions, { assumeDefaults });
  const check = modelCheck(model);
  return { version: VERSION, scan, labels, model, check };
}
