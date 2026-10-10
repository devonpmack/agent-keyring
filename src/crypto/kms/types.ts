// A KMS wraps and unwraps data keys. The master key never leaves the KMS (or,
// for the local dev adapter, never leaves a key file outside the database).
// `context` is bound as additional authenticated data, so a wrapped key copied
// onto another row or workspace fails to unwrap.
export interface Kms {
  readonly keyId: string;
  wrap(dataKey: Buffer, context: string): Promise<Buffer>;
  unwrap(wrapped: Buffer, keyId: string, context: string): Promise<Buffer>;
}
