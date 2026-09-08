import { readFileSync, readdirSync } from 'node:fs';
import type { FetchResult, TrustAnchors } from '../src/index.js';

const root = new URL('../fixtures/', import.meta.url).pathname;

export interface Case {
  name: string;
  id: string;
  text: string;
  marker: 'signed' | 'delegated';
  pageUrl: string | null;
  email?: { from: string; recipients: string[] };
  expect: { verdict: string; failedStep?: number; time?: string; grade?: string; claims?: unknown; coSigns?: string; coSignerCount?: number; reports?: number };
}

export const anchors: TrustAnchors = JSON.parse(readFileSync(`${root}anchors.json`, 'utf8'));
export const cases: Case[] = JSON.parse(readFileSync(`${root}index.json`, 'utf8'));
export const records = new Map<string, unknown>(
  readdirSync(`${root}records`).map((f) => [f.replace(/\.json$/, ''), JSON.parse(readFileSync(`${root}records/${f}`, 'utf8'))]),
);

export async function fetchRecord(id: string): Promise<FetchResult> {
  const r = records.get(id);
  return r ? { status: 'ok', record: r } : { status: 'not_found' };
}
