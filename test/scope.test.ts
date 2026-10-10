import { describe, expect, it } from 'vitest';
import { folderSchema, inScope, pathSchema } from '../src/domain/paths.js';
import { foldersOf } from '../src/domain/secrets.js';
import { parseTotpSeed } from '../src/domain/totp.js';

const secret = (folder: string, name: string, tags: string[] = []) => ({ folder, name, tags });

describe('grant scope', () => {
  it('a folder grant includes subfolders but not siblings', () => {
    const scope = { folder: 'prod', tags: [], names: [] };
    expect(inScope(scope, secret('prod', 'A'))).toBe(true);
    expect(inScope(scope, secret('prod/stripe', 'A'))).toBe(true);
    expect(inScope(scope, secret('production', 'A'))).toBe(false);
    expect(inScope(scope, secret('staging', 'A'))).toBe(false);
    expect(inScope(scope, secret('', 'A'))).toBe(false);
  });

  it('tags and names narrow the folder, never widen it', () => {
    const scope = { folder: 'prod', tags: ['ci'], names: [] };
    expect(inScope(scope, secret('prod', 'A', ['ci']))).toBe(true);
    expect(inScope(scope, secret('prod', 'B', ['billing']))).toBe(false);
    expect(inScope(scope, secret('staging', 'C', ['ci']))).toBe(false);
    const named = { folder: '', tags: [], names: ['prod/A'] };
    expect(inScope(named, secret('prod', 'A'))).toBe(true);
    expect(inScope(named, secret('prod', 'B'))).toBe(false);
  });

  it('lists ancestor folders', () => {
    expect(foldersOf([{ folder: 'prod/stripe' }, { folder: '' }, { folder: 'dev' }])).toEqual(['dev', 'prod', 'prod/stripe']);
  });
});

describe('input validation', () => {
  it('rejects traversal and odd characters in paths', () => {
    expect(pathSchema.safeParse('prod/../x').success).toBe(false);
    expect(pathSchema.safeParse('prod//x').success).toBe(false);
    expect(pathSchema.safeParse('prod/x y').success).toBe(false);
    expect(pathSchema.safeParse('prod/API_KEY').success).toBe(true);
    expect(folderSchema.parse('/prod/stripe/')).toBe('prod/stripe');
  });

  it('parses base32 seeds and otpauth URIs', () => {
    expect(parseTotpSeed('jbsw y3dp ehpk 3pxp').secret).toBe('JBSWY3DPEHPK3PXP');
    const p = parseTotpSeed('otpauth://totp/Acme:me?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256');
    expect(p).toEqual({ secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 60, algorithm: 'sha256' });
    expect(() => parseTotpSeed('not a seed!')).toThrow();
  });
});
