import { Request, Response } from 'express';
import { createLogger } from '@deepiri/shared-utils';
import prisma from './db';

const logger = createLogger('skill-tree-service');

const SKILLS: string[] = [
  'timeManagement', 'taskOrganization', 'focus', 'planning',
  'coding', 'debugging', 'codeReview', 'architecture',
  'writing', 'design', 'ideation', 'storytelling',
  'research', 'learning', 'noteTaking', 'knowledgeRetention',
  'collaboration', 'communication', 'leadership', 'mentoring',
  'selfAwareness', 'adaptability'
];

const XP_PER_LEVEL = 1000;
const MAX_LEVEL = 100;

class SkillTreeService {
  async getSkillTree(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      const skillTree = await this.getOrCreateSkillTree(userId);
      res.json(skillTree);
    } catch (error) {
      logger.error('Error getting skill tree:', error);
      res.status(500).json({ error: 'Failed to get skill tree' });
    }
  }

  async upgradeSkill(req: Request, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      const { skillName, xpAmount } = req.body;
      
      if (!skillName || !xpAmount) {
        res.status(400).json({ error: 'Missing skillName or xpAmount' });
        return;
      }

      const result = await this.awardSkillXP(userId, skillName, xpAmount);
      res.json(result);
    } catch (error) {
      logger.error('Error upgrading skill:', error);
      res.status(500).json({ error: 'Failed to upgrade skill' });
    }
  }

  private async getOrCreateSkillTree(userId: string) {
    try {
      let skillTree = await prisma.skillTree.findUnique({
        where: { userId },
        include: { skills: true }
      });
      
      if (!skillTree) {
        // Create skill tree
        skillTree = await prisma.skillTree.create({
          data: {
            userId,
            skills: {
              create: this._initializeSkills()
            }
          },
          include: { skills: true }
        });
      }
      
      // Convert to expected format
      const skillsObj: Record<string, any> = {};
      skillTree.skills.forEach((skill: any) => {
        skillsObj[skill.skillName] = {
          level: skill.level,
          xp: skill.xp,
          unlocked: skill.unlocked
        };
      });
      
      return {
        id: skillTree.id,
        userId: skillTree.userId,
        skills: skillsObj,
        skillPoints: skillTree.skillPoints,
        totalSkillLevel: skillTree.totalSkillLevel,
        lastUpdated: skillTree.lastUpdated
      };
    } catch (error) {
      logger.error('Error getting skill tree:', error);
      throw error;
    }
  }

  private _initializeSkills() {
    return SKILLS.map(skillName => ({
      skillName,
      level: 1,
      xp: 0,
      unlocked: true
    }));
  }

  private async awardSkillXP(userId: string, skillName: string, xpAmount: number) {
    try {
      const skillTree = await this.getOrCreateSkillTree(userId);
      
      if (!SKILLS.includes(skillName)) {
        throw new Error(`Invalid skill: ${skillName}`);
      }
      
      // Find or create skill
      let skill = await prisma.skill.findFirst({
        where: {
          skillTreeId: skillTree.id,
          skillName
        }
      });

      if (!skill) {
        skill = await prisma.skill.create({
          data: {
            skillTreeId: skillTree.id,
            skillName,
            level: 1,
            xp: 0,
            unlocked: true
          }
        });
      }
      
      const newXp = skill.xp + xpAmount;
      const newLevel = Math.floor(newXp / XP_PER_LEVEL) + 1;
      const leveledUp = newLevel > skill.level && newLevel <= MAX_LEVEL;
      
      const updatedSkill = await prisma.skill.update({
        where: { id: skill.id },
        data: {
          xp: newXp,
          level: leveledUp ? newLevel : skill.level,
          unlocked: true
        }
      });

      if (leveledUp) {
        await prisma.skillTree.update({
          where: { id: skillTree.id },
          data: {
            skillPoints: { increment: 1 },
            totalSkillLevel: { increment: 1 },
            lastUpdated: new Date()
          }
        });
      } else {
        await prisma.skillTree.update({
          where: { id: skillTree.id },
          data: {
            lastUpdated: new Date()
          }
        });
      }
      
      return {
        skill: skillName,
        level: updatedSkill.level,
        xp: updatedSkill.xp,
        leveledUp,
        skillPoints: skillTree.skillPoints + (leveledUp ? 1 : 0)
      };
    } catch (error) {
      logger.error('Error awarding skill XP:', error);
      throw error;
    }
  }
}

export default new SkillTreeService();
