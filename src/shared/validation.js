const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;
const CONTAINER_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/;

export function assertIdentifier(value, field = 'id') {
  if (!ID_PATTERN.test(String(value ?? ''))) {
    throw new Error(`${field} must match ${ID_PATTERN}`);
  }
  return String(value);
}

export function assertContainerName(value) {
  if (!CONTAINER_PATTERN.test(String(value ?? ''))) {
    throw new Error(`container must match ${CONTAINER_PATTERN}`);
  }
  return String(value);
}

export function assertAction(value) {
  if (!['start', 'stop', 'restart'].includes(value)) {
    throw new Error('action must be start, stop, or restart');
  }
  return value;
}
