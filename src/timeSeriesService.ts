import { Request, Response } from 'express';
import { createLogger } from '@deepiri/shared-utils';
import prisma from './db';

const logger = createLogger('time-series-service');

class TimeSeriesService {
  async recordData(req: Request, res: Response): Promise<void> {
    try {
      const { userId, metric, value, metadata } = req.body;
      
      if (!userId || !metric || value === undefined) {
        res.status(400).json({ error: 'Missing required fields' });
        return;
      }

      const point = await this.recordProgress(userId, metric, value, metadata || {});
      res.json(point);
    } catch (error) {
      logger.error('Error recording data:', error);
      res.status(500).json({ error: 'Failed to record data' });
    }
  }

  async getData(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      const { metric, startDate, endDate } = req.query;
      
      if (!metric || !startDate || !endDate) {
        res.status(400).json({ error: 'Missing query parameters' });
        return;
      }

      const series = await this.getProgressSeries(
        userId,
        metric as string,
        new Date(startDate as string),
        new Date(endDate as string)
      );
      res.json(series);
    } catch (error) {
      logger.error('Error getting data:', error);
      res.status(500).json({ error: 'Failed to get data' });
    }
  }

  private async recordProgress(userId: string, metric: string, value: number, metadata: Record<string, any> = {}) {
    try {
      const point = await prisma.progressPoint.create({
        data: {
          userId,
          metricType: metric,
          value,
          timestamp: new Date(),
          metadata: metadata as any
        }
      });

      logger.debug('Progress point recorded', { userId, metric, value });
      return point;
    } catch (error) {
      logger.error('Error recording progress:', error);
      throw error;
    }
  }

  private async getProgressSeries(userId: string, metric: string, startDate: Date, endDate: Date) {
    try {
      const points = await prisma.progressPoint.findMany({
        where: {
          userId,
          metricType: metric,
          timestamp: {
            gte: startDate,
            lte: endDate
          }
        },
        select: {
          timestamp: true,
          value: true,
          metadata: true
        },
        orderBy: {
          timestamp: 'asc'
        }
      });

      return points;
    } catch (error) {
      logger.error('Error getting progress series:', error);
      throw error;
    }
  }
}

export default new TimeSeriesService();
