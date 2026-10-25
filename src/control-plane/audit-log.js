import { appendFile, mkdir, open, readFile, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';

function hashRecord(record) {
  return createHash('sha256').update(JSON.stringify(record)).digest('hex');
}

export class AuditLog {
  #queue = Promise.resolve();

  constructor(file) {
    this.file = file;
    this.previousHash = '0'.repeat(64);
  }

  async init() {
    await mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    await this.#verifyFile();
  }

  async #verifyFile() {
    try {
      const lines = (await readFile(this.file, 'utf8')).trim().split('\n').filter(Boolean);
      let previous = '0'.repeat(64);
      for (const line of lines) {
        const entry = JSON.parse(line);
        const { hash, ...record } = entry;
        if (record.previousHash !== previous || hashRecord(record) !== hash) {
          throw new Error('audit hash chain verification failed');
        }
        previous = hash;
      }
      this.previousHash = previous;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  append(event) {
    const run = async () => {
      const release = await this.#acquireFileLock();
      try {
        await this.#verifyFile();
        const record = {
          timestamp: new Date().toISOString(),
          ...event,
          previousHash: this.previousHash,
        };
        const entry = { ...record, hash: hashRecord(record) };
        await appendFile(this.file, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
        this.previousHash = entry.hash;
        return entry;
      } finally {
        await release();
      }
    };
    const next = this.#queue.then(run, run);
    this.#queue = next.then(() => undefined, () => undefined);
    return next;
  }

  async recent(limit = 100) {
    try {
      const lines = (await readFile(this.file, 'utf8')).trim().split('\n').filter(Boolean);
      return lines.slice(-Math.max(1, Math.min(limit, 500))).reverse().map(JSON.parse);
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw error;
    }
  }

  async #acquireFileLock() {
    const lockFile = `${this.file}.lock`;
    const deadline = Date.now() + 5000;
    while (true) {
      try {
        const handle = await open(lockFile, 'wx', 0o600);
        await handle.writeFile(`${process.pid} ${Date.now()}\n`);
        await handle.close();
        return async () => { await unlink(lockFile).catch(() => {}); };
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        try {
          if (Date.now() - (await stat(lockFile)).mtimeMs > 30_000) {
            await unlink(lockFile);
            continue;
          }
        } catch (lockError) {
          if (lockError.code === 'ENOENT') continue;
          throw lockError;
        }
        if (Date.now() >= deadline) throw new Error('audit log is locked by another process');
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
  }
}
