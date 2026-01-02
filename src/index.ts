import express, { Router, Request, Response } from 'express';
import oauthService from './oauthService';
import skillTreeService from './skillTreeService';
import socialGraphService from './socialGraphService';
import timeSeriesService from './timeSeriesService';
import authService from './authService';

const router: Router = express.Router();

// Auth routes
router.post('/auth/login', (req: Request, res: Response) => authService.login(req, res));
router.post('/auth/register', (req: Request, res: Response) => authService.register(req, res));
router.post('/auth/google', (req: Request, res: Response) => authService.googleLogin(req, res));
router.get('/auth/verify', (req: Request, res: Response) => authService.verify(req, res));
router.post('/auth/refresh', (req: Request, res: Response) => authService.refresh(req, res));
router.post('/auth/logout', (req: Request, res: Response) => authService.logout(req, res));
router.post('/auth/forgot-password', (req: Request, res: Response) => authService.forgotPassword(req, res));
router.post('/auth/reset-password', (req: Request, res: Response) => authService.resetPassword(req, res));

// OAuth routes
router.post('/oauth/authorize', (req: Request, res: Response) => oauthService.authorize(req, res));
router.post('/oauth/token', (req: Request, res: Response) => oauthService.token(req, res));
router.post('/oauth/register', (req: Request, res: Response) => oauthService.registerClient(req, res));

// Skill tree routes
router.get('/skill-tree/:userId', (req: Request, res: Response) => skillTreeService.getSkillTree(req, res));
router.post('/skill-tree/:userId/upgrade', (req: Request, res: Response) => skillTreeService.upgradeSkill(req, res));

// Social graph routes
router.get('/social/:userId/friends', (req: Request, res: Response) => socialGraphService.getFriends(req, res));
router.post('/social/:userId/friends', (req: Request, res: Response) => socialGraphService.addFriend(req, res));

// Time series routes
router.post('/time-series/record', (req: Request, res: Response) => timeSeriesService.recordData(req, res));
router.get('/time-series/:userId', (req: Request, res: Response) => timeSeriesService.getData(req, res));

export default router;

