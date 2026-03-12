import express, { Router, Request, Response } from 'express';
import { validate, commonValidations } from './middleware/inputValidation';
import { param, query, header, body } from 'express-validator';
import oauthService from './oauthService';
import skillTreeService from './skillTreeService';
import socialGraphService from './socialGraphService';
import timeSeriesService from './timeSeriesService';
import authService from './authService';

const router: Router = express.Router();

// Auth routes
router.post('/auth/login',
  validate([commonValidations.email, commonValidations.password]),
  (req: Request, res: Response) => authService.login(req, res)
);

router.post('/auth/register',
  validate([
    commonValidations.email,
    commonValidations.password,
    commonValidations.string('username', 50),
    commonValidations.string('firstName', 100).optional(),
    commonValidations.string('lastName', 100).optional()
  ]),
  (req: Request, res: Response) => authService.register(req, res)
);
router.get('/auth/verify',
  validate([
    header('authorization')
      .notEmpty()
      .withMessage('Authorization header required')
      .matches(/^Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]*$/)
      .withMessage('Invalid JWT format')
  ]),
  (req: Request, res: Response) => authService.verify(req, res)
);

router.post('/auth/refresh',
  validate([
    body('refreshToken')
      .notEmpty()
      .withMessage('Refresh token required')
      .isLength({ min: 10, max: 2000 })
      .withMessage('Invalid refresh token format')
  ]),
  (req: Request, res: Response) => authService.refresh(req, res)
);
router.post('/auth/logout',
  validate([
    header('authorization')
      .notEmpty()
      .withMessage('Authorization header required')
  ]),
  (req: Request, res: Response) => authService.logout(req, res)
);

router.post('/auth/forgot-password',
  validate([commonValidations.email]),
  (req: Request, res: Response) => authService.forgotPassword(req, res)
);

router.post('/auth/reset-password',
  validate([
    commonValidations.string('token', 1000),
    commonValidations.password
  ]),
  (req: Request, res: Response) => authService.resetPassword(req, res)
);

// OAuth routes
router.post('/oauth/authorize',
  validate([
    body('clientId')
      .notEmpty()
      .isUUID()
      .withMessage('Invalid client ID'),
    body('redirectUri')
      .notEmpty()
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Invalid redirect URI')
      .isLength({ max: 2048 })
      .withMessage('Redirect URI must be less than 2048 characters'),
    body('scopes')
      .isArray()
      .withMessage('Scopes must be an array'),
    body('responseType')
      .isIn(['code', 'token', 'id_token'])
      .withMessage('Invalid response type')
  ]),
  (req: Request, res: Response) => oauthService.authorize(req, res)
);

router.post('/oauth/token',
  validate([
    body('grantType')
      .notEmpty()
      .isIn(['authorization_code', 'refresh_token', 'client_credentials'])
      .withMessage('Invalid grant type'),
    body('clientId')
      .notEmpty()
      .isUUID()
      .withMessage('Invalid client ID'),
    body('clientSecret')
      .notEmpty()
      .isLength({ min: 32 })
      .withMessage('Invalid client secret'),
    body('code')
      .optional()
      .isLength({ min: 10, max: 2000 })
      .withMessage('Invalid authorization code'),
    body('refreshToken')
      .optional()
      .isLength({ min: 10, max: 2000 })
      .withMessage('Invalid refresh token')
  ]),
  (req: Request, res: Response) => oauthService.token(req, res)
);
router.post('/oauth/register',
  validate([
    body('clientName')
      .trim()
      .notEmpty()
      .isLength({ min: 2, max: 255 })
      .withMessage('Client name must be 2-255 characters'),
    body('redirectUris')
      .isArray({ min: 1, max: 50 })
      .withMessage('redirectUris must be an array of 1 to 50 items'),
    body('redirectUris.*')
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Each redirect URI must be a valid URL')
      .isLength({ max: 2048 })
      .withMessage('Each redirect URI must be less than 2048 characters'),
    body('scopes')
      .isArray()
      .withMessage('Scopes must be an array'),
    body('responseTypes')
      .isArray({ min: 1 })
      .withMessage('At least one response type required')
  ]),
  (req: Request, res: Response) => oauthService.registerClient(req, res)
);

// Skill tree routes
router.get('/skill-tree/:userId',
  validate([
    param('userId').isUUID().withMessage('Invalid user ID format')
  ]),
  (req: Request, res: Response) => skillTreeService.getSkillTree(req, res)
);

router.post('/skill-tree/:userId/upgrade',
  validate([
    param('userId').isUUID().withMessage('Invalid user ID format'),
    commonValidations.string('skillId', 100),
    commonValidations.integer('level', 1, 100)
  ]),
  (req: Request, res: Response) => skillTreeService.upgradeSkill(req, res)
);

// Social graph routes
router.get('/social/:userId/friends',
  validate([
    param('userId').isUUID().withMessage('Invalid user ID format')
  ]),
  (req: Request, res: Response) => socialGraphService.getFriends(req, res)
);

router.post('/social/:userId/friends',
  validate([
    param('userId').isUUID().withMessage('Invalid user ID format'),
    commonValidations.string('friendId', 100)
  ]),
  (req: Request, res: Response) => socialGraphService.addFriend(req, res)
);

// Time series routes
router.post('/time-series/record',
  validate([
    commonValidations.string('metric', 100),
    commonValidations.integer('value', -1000000, 1000000),
    query('timestamp').optional().isISO8601().withMessage('Invalid timestamp format')
  ]),
  (req: Request, res: Response) => timeSeriesService.recordData(req, res)
);

router.get('/time-series/:userId',
  validate([
    param('userId').isUUID().withMessage('Invalid user ID format'),
    query('metric').optional().isLength({ max: 100 }).withMessage('Metric must be less than 100 characters'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date format')
  ]),
  (req: Request, res: Response) => timeSeriesService.getData(req, res)
);

export default router;

