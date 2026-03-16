import mongoose, {
  Document,
  Model,
  Schema,
  Types,
  HydratedDocument,
} from 'mongoose';

import { ApiKeyScope, ApiKeyCachePayload } from '@deepiri/shared-utils/src/types';

export interface IApiKey {
  hashedKey:       string;
  label:           string;
  ownerId:         Types.ObjectId;
  scopes:          ApiKeyScope[];
  revokedAt:       Date | null;
  expiresAt:       Date | null;
  lastUsedAt:      Date | null;
  createdAt?:      Date; 
  updatedAt?:      Date;
}

interface IApiKeyMethods {
  isActive():        boolean;
  toCachePayload():  ApiKeyCachePayload;
}

interface ApiKeyModel extends Model<IApiKey, {}, IApiKeyMethods> {
  findActiveByHash(
    hashedKey: string
  ): Promise<HydratedDocument<IApiKey, IApiKeyMethods> | null>;
}

const ApiKeySchema = new Schema<IApiKey, ApiKeyModel, IApiKeyMethods>(
  {
    hashedKey: {
      type:     String,
      required: [true, 'hashedKey is required.'],
      unique:   true,
      index:    true,
    },
    label: {
      type:    String,
      trim:    true,
      default: 'Unnamed Service Account',
    },
    ownerId: {
      type:     Schema.Types.ObjectId,
      ref:      'User',
      required: [true, 'ownerId is required.'],
      index:    true,
    },
    scopes: {
      type:     [String],
      enum:     ['ingestion:write', 'analytics:read', 'admin:all'] as ApiKeyScope[],
      default:  ['ingestion:write'],
      validate: {
        validator: (arr: string[]): boolean =>
          Array.isArray(arr) && arr.length > 0,
        message: 'At least one scope is required.',
      },
    },
    revokedAt: {
      type:    Date,
      default: null,
    },
    expiresAt: {
      type:    Date,
      default: null,
      index:   { expireAfterSeconds: 0, sparse: true }, 
    },
    lastUsedAt: {
      type:    Date,
      default: null,
    },
  },
  {
    timestamps:  true,
    collection:  'api_keys',
  }
);

ApiKeySchema.method('isActive', function (): boolean {
  if (this.revokedAt !== null) return false;
  if (this.expiresAt !== null && this.expiresAt < new Date()) return false;
  return true;
});

ApiKeySchema.method('toCachePayload', function (): ApiKeyCachePayload {
  return {
    serviceAccountId: (this._id as Types.ObjectId).toString(),
    ownerId:          this.ownerId.toString(),
    scopes:           this.scopes,
    label:            this.label,
  };
});

ApiKeySchema.static(
  'findActiveByHash',
  async function (
    hashedKey: string
  ): Promise<HydratedDocument<IApiKey, IApiKeyMethods> | null> {
    return this.findOne({
      hashedKey,
      revokedAt: null,
      $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
    });
  }
);

export const ApiKey = mongoose.model<IApiKey, ApiKeyModel>('ApiKey', ApiKeySchema);