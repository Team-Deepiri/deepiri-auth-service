import prisma from '../db';
import { ApiKeyScope, ApiKeyCachePayload } from '@team-deepiri/shared-utils';
import type { ApiKey as PrismaApiKey } from '@prisma/client';

export interface IApiKey {
  id: string;
  hashedKey: string;
  label: string;
  ownerId: string;
  scopes: string[];
  revokedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  lastUsedAt: Date | null;
}

export class ApiKeyModel {
  private apikey: IApiKey;

  constructor(apikey: IApiKey) {
    this.apikey = apikey;
  }

  // Getters for compatibility
  get id() { return this.apikey.id; }
  get hashedKey() { return this.apikey.hashedKey; }
  get label() { return this.apikey.label; }
  get ownerId() { return this.apikey.ownerId; }
  get scopes() { return this.apikey.scopes as ApiKeyScope[]; }
  get revokedAt() { return this.apikey.revokedAt; }
  get expiresAt() { return this.apikey.expiresAt; }
  get createdAt() { return this.apikey.createdAt; }
  get updatedAt() { return this.apikey.updatedAt; }
  get _id() { return this.apikey.id; } // Alias for any lingering Mongo _id references

  get lastUsedAt() { return this.apikey.lastUsedAt; }
  set lastUsedAt(val: Date | null) { this.apikey.lastUsedAt = val; }

  /**
   * Check if the API key is active.
   */
  isActive(): boolean {
    if (this.revokedAt !== null) return false;
    if (this.expiresAt !== null && this.expiresAt < new Date()) return false;
    return true;
  }

  /**
   * Format payload for Redis cache.
   */
  toCachePayload(): ApiKeyCachePayload {
    return {
      serviceAccountId: this.id,
      ownerId: this.ownerId,
      scopes: this.scopes,
      label: this.label,
    };
  }

  /**
   * Save changes to the database (currently only used for lastUsedAt updates).
   */
  async save(): Promise<void> {
    await prisma.apiKey.update({
      where: { id: this.id },
      data: {
        lastUsedAt: this.lastUsedAt,
      },
    });
  }

  /**
   * Find an active API key by its hash.
   */
  static async findActiveByHash(hashedKey: string): Promise<ApiKeyModel | null> {
    const key = await prisma.apiKey.findFirst({
      where: {
        hashedKey,
        revokedAt: null,
        OR: [
          { expiresAt: null },
          { expiresAt: { gt: new Date() } }
        ]
      }
    });

    if (!key) return null;
    return new ApiKeyModel(key as IApiKey);
  }
}

// Export as ApiKey to match the old Mongoose model export
export const ApiKey = ApiKeyModel;
