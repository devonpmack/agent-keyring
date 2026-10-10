import { DecryptCommand, EncryptCommand, KMSClient } from '@aws-sdk/client-kms';
import type { Kms } from './types.js';

type AwsKmsClient = Pick<KMSClient, 'send'>;

// AWS binds the context as an EncryptionContext, which also shows up in CloudTrail.
export class AwsKms implements Kms {
  constructor(
    readonly keyId: string,
    private readonly client: AwsKmsClient,
  ) {}

  static create(keyId: string, region?: string): AwsKms {
    return new AwsKms(keyId, new KMSClient(region ? { region } : {}));
  }

  async wrap(dataKey: Buffer, context: string): Promise<Buffer> {
    const res = await this.client.send(
      new EncryptCommand({ KeyId: this.keyId, Plaintext: dataKey, EncryptionContext: { purpose: context } }),
    );
    if (!res.CiphertextBlob) throw new Error('KMS encrypt returned no ciphertext');
    return Buffer.from(res.CiphertextBlob);
  }

  async unwrap(wrapped: Buffer, keyId: string, context: string): Promise<Buffer> {
    const res = await this.client.send(
      new DecryptCommand({ KeyId: keyId, CiphertextBlob: wrapped, EncryptionContext: { purpose: context } }),
    );
    if (!res.Plaintext) throw new Error('KMS decrypt returned no plaintext');
    return Buffer.from(res.Plaintext);
  }
}
