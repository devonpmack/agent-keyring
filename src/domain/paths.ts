import { z } from 'zod';

// Folders are slash-separated segments ("prod/stripe"); "" is the root.
// A secret's path is its folder plus its name ("prod/stripe/API_KEY").
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const MAX_DEPTH = 8;

export const segmentSchema = z.string().regex(SEGMENT, 'use letters, digits, "_", "." or "-" (max 64)');

export const folderSchema = z
  .string()
  .trim()
  .transform(s => s.replace(/^\/+|\/+$/g, ''))
  .refine(s => s === '' || (s.split('/').length <= MAX_DEPTH && s.split('/').every(seg => SEGMENT.test(seg))), {
    message: 'folder segments must use letters, digits, "_", "." or "-"',
  });

export const pathSchema = z
  .string()
  .trim()
  .max(600)
  .transform(s => s.replace(/^\/+/, ''))
  .refine(s => s.split('/').length <= MAX_DEPTH + 1 && s.split('/').every(seg => SEGMENT.test(seg)), {
    message: 'invalid secret path',
  });

export const tagSchema = z.string().trim().regex(/^[a-z0-9][a-z0-9_-]{0,31}$/, 'tags are lowercase, max 32 chars');

export function splitPath(path: string): { folder: string; name: string } {
  const idx = path.lastIndexOf('/');
  if (idx === -1) return { folder: '', name: path };
  return { folder: path.slice(0, idx), name: path.slice(idx + 1) };
}

export function joinPath(folder: string, name: string): string {
  return folder ? `${folder}/${name}` : name;
}

export function folderContains(scopeFolder: string, folder: string): boolean {
  return scopeFolder === '' || folder === scopeFolder || folder.startsWith(scopeFolder + '/');
}

export type GrantScope = { folder: string; tags: string[]; names: string[] };

// Every condition narrows: the folder must contain the secret, and if tags or
// names are set the secret must also match one of each.
export function inScope(scope: GrantScope, secret: { folder: string; name: string; tags: string[] }): boolean {
  if (!folderContains(scope.folder, secret.folder)) return false;
  if (scope.tags.length > 0 && !secret.tags.some(t => scope.tags.includes(t))) return false;
  if (scope.names.length > 0 && !scope.names.includes(joinPath(secret.folder, secret.name))) return false;
  return true;
}

export function describeScope(scope: GrantScope): string {
  const parts = [scope.folder === '' ? 'all folders' : `folder ${scope.folder}/`];
  if (scope.tags.length) parts.push(`tags: ${scope.tags.join(', ')}`);
  if (scope.names.length) parts.push(`only: ${scope.names.join(', ')}`);
  return parts.join(' · ');
}
