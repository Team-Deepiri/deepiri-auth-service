import internalRoutes from './routes/internal.routes';
import express, { Router, Request, Response } from 'express';
import { validate, commonValidations } from './middleware/inputValidation';
import { param, query, header, body } from 'express-validator';
import oauthService from './oauthService';
import skillTreeService from './skillTreeService';
import socialGraphService from './socialGraphService';
import timeSeriesService from './timeSeriesService';
import authService from './authService';

const router: Router = express.Router();
// Internal service routes
router.use('/internal', internalRoutes);
// Auth routes
router.post('/auth/login',
  validate([commonValidations.email, commonValidations.password], { allowedBodyFields: ['email', 'password'] }),
  (req: Request, res: Response) => authService.login(req, res)
);

router.post('/auth/register',
  validate([
    commonValidations.email,
    commonValidations.password,
    commonValidations.string('username', 200),
  ], { allowedBodyFields: ['email', 'password', 'username'] }),
  (req: Request, res: Response) => authService.register(req, res)
);
router.get('/auth/check-email',
  validate([
    query('email').trim().notEmpty().isEmail().withMessage('Valid email is required').isLength({ max: 255 }),
  ], { allowedQueryFields: ['email'] }),
  (req: Request, res: Response) => authService.checkEmail(req, res)
);
router.get('/auth/verify',
  validate([
    header('authorization')
      .trim()
      .notEmpty()
      .withMessage('Authorization header required')
      .matches(/^Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]*$/)
      .withMessage('Invalid JWT format')
  ], { allowedHeaderFields: ['authorization', 'x-request-id', 'x-api-key'] }),
  (req: Request, res: Response) => authService.verify(req, res)
);

router.post('/auth/refresh',
  validate([
    header('authorization')
      .trim()
      .notEmpty()
      .withMessage('Authorization header required')
      .matches(/^Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]*$/)
      .withMessage('Invalid JWT format')
  ], { allowedHeaderFields: ['authorization', 'x-request-id', 'x-api-key'] }),
  (req: Request, res: Response) => authService.refresh(req, res)
);
router.post('/auth/logout',
  validate([
    header('authorization')
      .trim()
      .notEmpty()
      .withMessage('Authorization header required')
  ], { allowedHeaderFields: ['authorization', 'x-request-id', 'x-api-key'] }),
  (req: Request, res: Response) => authService.logout(req, res)
);

router.post('/auth/forgot-password',
  validate([commonValidations.email], { allowedBodyFields: ['email'] }),
  (req: Request, res: Response) => authService.forgotPassword(req, res)
);

router.post('/auth/reset-password',
  validate([
    commonValidations.string('token', 1000),
    commonValidations.password
  ], { allowedBodyFields: ['token', 'password'] }),
  (req: Request, res: Response) => authService.resetPassword(req, res)
);

// OAuth routes
router.post('/oauth/authorize',
  validate([
    body('clientId')
      .trim()
      .notEmpty()
      .isUUID()
      .withMessage('Invalid client ID'),
    body('redirectUri')
      .trim()
      .notEmpty()
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Invalid redirect URI')
      .isLength({ max: 2048 })
      .withMessage('Redirect URI must be less than 2048 characters'),
    body('scopes')
      .isArray()
      .withMessage('Scopes must be an array'),
    body('state')
      .optional()
      .trim()
      .isLength({ max: 512 })
      .withMessage('State must be less than 512 characters')
  ], { allowedBodyFields: ['clientId', 'redirectUri', 'scopes', 'state'] }),
  (req: Request, res: Response) => oauthService.authorize(req, res)
);

router.post('/oauth/token',
  validate([
    body('code')
      .trim()
      .notEmpty()
      .isLength({ min: 10, max: 2000 })
      .withMessage('Invalid authorization code'),
    body('clientId')
      .trim()
      .notEmpty()
      .isUUID()
      .withMessage('Invalid client ID'),
    body('clientSecret')
      .trim()
      .notEmpty()
      .isLength({ min: 32 })
      .withMessage('Invalid client secret'),
    body('redirectUri')
      .trim()
      .notEmpty()
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Invalid redirect URI')
      .isLength({ max: 2048 })
      .withMessage('Redirect URI must be less than 2048 characters'),
  ], { allowedBodyFields: ['code', 'clientId', 'clientSecret', 'redirectUri'] }),
  (req: Request, res: Response) => oauthService.token(req, res)
);
router.post('/oauth/register',
  validate([
    body('clientId')
      .trim()
      .notEmpty()
      .isUUID()
      .withMessage('Invalid client ID'),
    body('clientSecret')
      .trim()
      .notEmpty()
      .isLength({ min: 32, max: 256 })
      .withMessage('Client secret must be 32-256 characters'),
    body('redirectUris')
      .isArray({ min: 1, max: 50 })
      .withMessage('redirectUris must be an array of 1 to 50 items'),
    body('redirectUris.*')
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Each redirect URI must be a valid URL')
      .isLength({ max: 2048 })
      .withMessage('Each redirect URI must be less than 2048 characters'),
    body('scopes')
      .isArray({ min: 1 })
      .withMessage('Scopes must be a non-empty array'),
  ], { allowedBodyFields: ['clientId', 'clientSecret', 'redirectUris', 'scopes'] }),
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
    commonValidations.string('skillName', 100),
    commonValidations.integer('xpAmount', 1, 1_000_000)
  ], { allowedBodyFields: ['skillName', 'xpAmount'] }),
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
    body('targetUserId')
      .trim()
      .notEmpty()
      .isUUID()
      .withMessage('Invalid target user ID format'),
  ], { allowedBodyFields: ['targetUserId'] }),
  (req: Request, res: Response) => socialGraphService.addFriend(req, res)
);

// Time series routes
router.post('/time-series/record',
  validate([
    body('userId')
      .trim()
      .notEmpty()
      .isUUID()
      .withMessage('Invalid user ID format'),
    commonValidations.string('metric', 100),
    commonValidations.integer('value', -1000000, 1000000),
    body('metadata')
      .optional()
      .isObject()
      .withMessage('Metadata must be an object'),
  ], { allowedBodyFields: ['userId', 'metric', 'value', 'metadata'] }),
  (req: Request, res: Response) => timeSeriesService.recordData(req, res)
);

router.get('/time-series/:userId',
  validate([
    param('userId').isUUID().withMessage('Invalid user ID format'),
    query('metric').optional().trim().isLength({ max: 100 }).withMessage('Metric must be less than 100 characters'),
    query('startDate').optional().trim().isISO8601().withMessage('Invalid start date format'),
    query('endDate').optional().trim().isISO8601().withMessage('Invalid end date format')
  ], { allowedQueryFields: ['metric', 'startDate', 'endDate'] }),
  (req: Request, res: Response) => timeSeriesService.getData(req, res)
);

export default router;

