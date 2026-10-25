import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

export class OperationError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

export class OperationLedger {
  #queue = Promise.resolve();

  constructor(file, { maximumEntries = 1000 } = {}) {
    this.file = file;
    this.maximumEntries = maximumEntries;
  }

  async init() {
    await mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    try {
      await readFile(this.file);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      await this.#write({ version: 1, operations: {} });
    }
  }

  async read() {
    return JSON.parse(await readFile(this.file, 'utf8'));
  }

  transaction(mutator) {
    const run = async () => {
      const state = await this.read();
      const result = await mutator(state);
      await this.#write(state);
      return result;
    };
    const next = this.#queue.then(run, run);
    this.#queue = next.then(() => undefined, () => undefined);
    return next;
  }

  async begin(command) {
    return this.transaction((state) => {
      const existing = state.operations[command.commandId];
      if (existing) return { existing };
      const conflict = Object.values(state.operations).find((operation) => operation.container === command.container && operation.state === 'started');
      if (conflict) throw new OperationError(`container has unresolved command ${conflict.commandId}`, 'CONFLICT');
      const entry = {
        commandId: command.commandId,
        container: command.container,
        action: command.action,
        state: 'started',
        startedAt: new Date().toISOString(),
      };
      state.operations[command.commandId] = entry;
      this.#prune(state);
      return { entry };
    });
  }

  async complete(commandId, result) {
    return this.transaction((state) => {
      const entry = state.operations[commandId];
      if (!entry) throw new Error('operation ledger entry missing');
      entry.state = 'completed';
      entry.completedAt = new Date().toISOString();
      entry.result = result;
      return entry;
    });
  }

  async reconcile(commandId, outcome, note = '') {
    if (!['succeeded', 'failed'].includes(outcome)) throw new Error('outcome must be succeeded or failed');
    return this.transaction((state) => {
      const entry = state.operations[commandId];
      if (!entry || entry.state !== 'started') throw new Error('unresolved command not found');
      entry.state = 'completed';
      entry.completedAt = new Date().toISOString();
      entry.result = { outcome: `reconciled-${outcome}`, note };
      return entry;
    });
  }

  #prune(state) {
    const completed = Object.values(state.operations).filter((entry) => entry.state === 'completed').sort((a, b) => Date.parse(a.completedAt) - Date.parse(b.completedAt));
    const removeCount = Math.max(0, Object.keys(state.operations).length - this.maximumEntries);
    for (const entry of completed.slice(0, removeCount)) delete state.operations[entry.commandId];
  }

  async #write(state) {
    const temporary = `${this.file}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporary, this.file);
  }
}

export class OperationExecutor {
  constructor({ ledger, execute }) {
    this.ledger = ledger;
    this.execute = execute;
    this.inFlight = new Map();
  }

  async run(command) {
    if (this.inFlight.has(command.commandId)) return this.inFlight.get(command.commandId);
    const promise = this.#run(command).finally(() => this.inFlight.delete(command.commandId));
    this.inFlight.set(command.commandId, promise);
    return promise;
  }

  async #run(command) {
    const begun = await this.ledger.begin(command);
    if (begun.existing) {
      if (begun.existing.state === 'completed') return { ...begun.existing.result, replayed: true };
      throw new OperationError('command has an indeterminate prior execution; reconcile it before retrying', 'INDETERMINATE');
    }
    try {
      const result = await this.execute(command);
      await this.ledger.complete(command.commandId, result);
      return result;
    } catch (error) {
      if (!error.indeterminate) {
        await this.ledger.complete(command.commandId, { outcome: 'failed', error: error.message });
      }
      throw error.indeterminate
        ? new OperationError('Docker outcome is indeterminate; manual reconciliation is required', 'INDETERMINATE')
        : error;
    }
  }
}
