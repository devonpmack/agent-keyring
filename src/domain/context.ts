import type { Config } from '../config.js';
import type { Kms } from '../crypto/kms/types.js';
import type { Db } from '../db/index.js';
import type { Notifier } from './notifier.js';

export interface Clock {
  now(): Date;
}

export const systemClock: Clock = { now: () => new Date() };

export interface AppContext {
  config: Config;
  db: Db;
  kms: Kms;
  clock: Clock;
  notifier: Notifier;
}

export function addSeconds(d: Date, seconds: number): Date {
  return new Date(d.getTime() + seconds * 1000);
}
