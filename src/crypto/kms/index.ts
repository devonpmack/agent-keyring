import type { Config } from '../../config.js';
import { AwsKms } from './aws.js';
import { GcpKms } from './gcp.js';
import { LocalKms } from './local.js';
import type { Kms } from './types.js';

export type { Kms } from './types.js';

export function createKms(config: Config['kms']): Kms {
  switch (config.provider) {
    case 'gcp':
      return new GcpKms(config.keyName);
    case 'aws':
      return AwsKms.create(config.keyId, config.region);
    case 'local':
      return LocalKms.fromFile(config.keyFile);
  }
}
