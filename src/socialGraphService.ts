import { Request, Response } from 'express';
import { createLogger } from '@team-deepiri/shared-utils';
import { secureLog } from '@team-deepiri/shared-utils';
import prisma from './db';

const logger = createLogger('social-graph-service');

type ConnectionType = 'friend' | 'follower' | 'following' | 'teammate' | 'rival';
type ConnectionStatus = 'pending' | 'accepted' | 'blocked';

class SocialGraphService {
  async getFriends(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      const connections = await this.getConnections(userId, 'friend', 'accepted');
      res.json(connections);
    } catch (error) {
      secureLog('error', 'Error getting friends:', error);
      res.status(500).json({ error: 'Failed to get friends' });
    }
  }

  async addFriend(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      const { targetUserId } = req.body;

      if (!targetUserId) {
        res.status(400).json({ error: 'Missing targetUserId' });
        return;
      }

      const connection = await this.sendFriendRequest(userId, targetUserId);
      res.json(connection);
    } catch (error) {
      secureLog('error', 'Error adding friend:', error);
      res.status(500).json({ error: 'Failed to add friend' });
    }
  }

  async sendFriendRequest(userId: string, targetUserId: string) {
    try {
      const connection = await prisma.$transaction(async (tx: any) => {
        const existing = await tx.socialConnection.findFirst({
          where: {
            OR: [
              { userId, connectedUserId: targetUserId },
              { userId: targetUserId, connectedUserId: userId }
            ]
          }
        });

        if (existing) {
          if (existing.status === 'blocked') {
            throw new Error('Cannot send request to blocked user');
          }
          if (existing.status === 'accepted') {
            return { message: 'Already connected', connection: existing } as any;
          }
          return { message: 'Request already pending', connection: existing } as any;
        }

        const created = await tx.socialConnection.create({
          data: {
            userId,
            connectedUserId: targetUserId,
            connectionType: 'friend',
            status: 'pending'
          },
          include: {
            connectedUser: {
              select: {
                id: true,
                name: true,
                email: true,
                avatarUrl: true
              }
            }
          }
        });

        await this._updateMetadata(userId, targetUserId, tx);
        return created;
      });

      logger.info('Friend request sent', { userId, targetUserId });
      return connection;
    } catch (error) {
      logger.error('Error sending friend request:', error);
      throw error;
    }
  }

  private async getConnections(userId: string, connectionType: ConnectionType | null = null, status: ConnectionStatus = 'accepted') {
    try {
      const where: any = { userId, status };
      if (connectionType) {
        where.connectionType = connectionType;
      }

      const connections = await prisma.socialConnection.findMany({
        where,
        include: {
          connectedUser: {
            select: {
              id: true,
              name: true,
              email: true,
              avatarUrl: true
            }
          }
        },
        orderBy: { updatedAt: 'desc' }
      });

      return connections.map((conn: any) => ({
        user: conn.connectedUser,
        connectionType: conn.connectionType,
        metadata: {
          mutualConnections: conn.mutualConnections,
          sharedChallenges: conn.sharedChallenges,
          collaborationScore: conn.collaborationScore
        },
        connectedAt: conn.createdAt
      }));
    } catch (error) {
      secureLog('error', 'Error getting connections:', error);
      throw error;
    }
  }

  private async _updateMetadata(userId1: string, userId2: string, db: any = prisma): Promise<void> {
    try {
      const mutual = await this.getMutualConnections(userId1, userId2, db);

      await db.socialConnection.updateMany({
        where: {
          OR: [
            { userId: userId1, connectedUserId: userId2 },
            { userId: userId2, connectedUserId: userId1 }
          ]
        },
        data: {
          mutualConnections: mutual.length
        }
      });
    } catch (error) {
      logger.error('Error updating metadata:', error);
    }
  }

  private async getMutualConnections(userId1: string, userId2: string, db: any = prisma) {
    try {
      const user1Connections = await db.socialConnection.findMany({
        where: {
          userId: userId1,
          status: 'accepted'
        },
        select: { connectedUserId: true }
      });

      const user2Connections = await db.socialConnection.findMany({
        where: {
          userId: userId2,
          status: 'accepted'
        },
        select: { connectedUserId: true }
      });

      const user1Ids = new Set(user1Connections.map((c: any) => c.connectedUserId));
      const user2Ids = new Set(user2Connections.map((c: any) => c.connectedUserId));

      const mutualIds = [...user1Ids].filter(id => user2Ids.has(id));

      const mutualConnections = await db.user.findMany({
        where: {
          id: { in: mutualIds }
        },
        select: {
          id: true,
          name: true,
          email: true,
          avatarUrl: true
        }
      });

      return mutualConnections;
    } catch (error) {
      secureLog('error', 'Error getting mutual connections:', error);
      throw error;
    }
  }
}

export default new SocialGraphService();
