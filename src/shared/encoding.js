import { createHash, timingSafeEqual } from 'node:crypto';

export function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

export function fromBase64url(input) {
  return Buffer.from(input, 'base64url');
}

export function sha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

export function constantEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

export function canonicalContainers(containers) {
  return [...new Set(containers.map((value) => String(value).trim()).filter(Boolean))].sort();
}

export function sameStringArray(left, right) {
  const a = canonicalContainers(left);
  const b = canonicalContainers(right);
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
