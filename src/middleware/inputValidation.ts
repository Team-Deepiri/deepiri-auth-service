/*About: This file addresses the following security risks:
missing validation on some endpoints
inconsistent validation patterns
no length limits on inputs
*/

//import the types for Express requests and middleware
//import tools to validate input
//import the logger to log errors, warnings, or debug info
import { Request, Response, NextFunction } from 'express';
import { body, validationResult, ValidationChain } from 'express-validator';
import { logger } from '../utils/logger';
import { sanitizeObject } from '../utils/sanitizers';

interface ValidationOptions {
  allowedBodyFields?: string[];
  allowedQueryFields?: string[];
  allowedHeaderFields?: string[];
}

const isApplicationHeader = (headerName: string): boolean => {
  const normalizedHeaderName = headerName.toLowerCase();
  return normalizedHeaderName === 'authorization' || normalizedHeaderName.startsWith('x-');
};

const sanitizeValue = (value: unknown): unknown => {
  if (typeof value === 'string') {
    return value.trim();
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }

  if (value && typeof value === 'object') {
    const sanitizedRecord: Record<string, unknown> = {};
    for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
      sanitizedRecord[key] = sanitizeValue(nestedValue);
    }
    return sanitizedRecord;
  }

  return value;
};

// Common validation rules
export const commonValidations = {
  //Email validation: list common rules to reuse for validating email addresses
  email: body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email format')
    .isLength({ max: 255 })
    .withMessage('Email must be less than 255 characters'),

  //Password validation: enforce secure password length,
  //use regex to check for required characters
  password: body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character'),

  //User ID validation: validates UUID format, makes field
  //optional for partial updates
  userId: body('userId')
    .isUUID()
    .withMessage('Invalid user ID format')
    .optional(),

  //String validation: rule for any text field- trims extra spaces,
  //checks length of the string, sets up error message
  string: (field: string, maxLength: number = 1000) =>
    body(field)
      .trim()
      .notEmpty()
      .withMessage(`${field} is required`)
      .isLength({ max: maxLength })
      .withMessage(`${field} must be less than ${maxLength} characters`)
      .escape(),

  //URL Validation: only allows HTTP/HTTPS protocols,
  //length limits prevent DoS attacks
  url: (field: string) =>
    body(field)
      .trim()
      .isURL({ protocols: ['http', 'https'] })
      .withMessage('Invalid URL format')
      .isLength({ max: 2048 })
      .withMessage('URL must be less than 2048 characters'),

  //Check if input is an integer, within the specified range,
  // shows error message otherwise
  integer: (field: string, min: number = 0, max: number = Number.MAX_SAFE_INTEGER) =>
    body(field)
      .toInt()
      .isInt({ min, max })
      .withMessage(`${field} must be an integer between ${min} and ${max}`),

  //Validation rule for array fields- check for input type,
  // length of array, shows error message
  //if invalid
  array: (field: string, maxItems: number = 100) =>
    body(field)
      .isArray()
      .custom((arr: any) => {
        if (!Array.isArray(arr) || arr.length > maxItems) {
          throw new Error(`${field} must be an array with at most ${maxItems} items`);
        }
        return true;
      }),
};

// Validation middleware
export const validate = (validations: ValidationChain[], options: ValidationOptions = {}) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    // Run all validations
    await Promise.all(validations.map(validation => validation.run(req)));

    const requestId = (req as any).requestId || 'unknown';

    const bodyValidationErrors: Array<{ path: string; msg: string; value: unknown }> = [];
    const queryValidationErrors: Array<{ path: string; msg: string; value: unknown }> = [];
    const headerValidationErrors: Array<{ path: string; msg: string; value: unknown }> = [];

    if (options.allowedBodyFields && req.body && typeof req.body === 'object' && !Array.isArray(req.body)) {
      const unknownFields = Object.keys(req.body).filter(
        (field) => !options.allowedBodyFields?.includes(field)
      );

      if (unknownFields.length > 0) {
        bodyValidationErrors.push({
          path: 'body',
          msg: `Unknown fields provided: ${unknownFields.join(', ')}`,
          value: unknownFields,
        });
      }
    }

    if (options.allowedQueryFields && req.query && typeof req.query === 'object') {
      const unknownQueryFields = Object.keys(req.query).filter(
        (field) => !options.allowedQueryFields?.includes(field)
      );

      if (unknownQueryFields.length > 0) {
        queryValidationErrors.push({
          path: 'query',
          msg: `Unknown query fields provided: ${unknownQueryFields.join(', ')}`,
          value: unknownQueryFields,
        });
      }
    }

    if (options.allowedHeaderFields && req.headers && typeof req.headers === 'object') {
      const normalizedAllowedHeaderFields = options.allowedHeaderFields.map((field) => field.toLowerCase());
      const unknownHeaderFields = Object.keys(req.headers).filter(
        (field) =>
          isApplicationHeader(field) &&
          !normalizedAllowedHeaderFields.includes(field.toLowerCase())
      );

      if (unknownHeaderFields.length > 0) {
        headerValidationErrors.push({
          path: 'headers',
          msg: `Unknown headers provided: ${unknownHeaderFields.join(', ')}`,
          value: unknownHeaderFields,
        });
      }
    }

    //collect any errors found
    const errors = validationResult(req);
    if (!errors.isEmpty() || bodyValidationErrors.length > 0 || queryValidationErrors.length > 0 || headerValidationErrors.length > 0) {
      const allErrors = [
        ...errors.array(),
        ...bodyValidationErrors,
        ...queryValidationErrors,
        ...headerValidationErrors,
      ];

      //log the failure
      logger.warn('Validation failed', {
        requestId,
        path: req.path,
        method: req.method,
        errors: allErrors,
      });

      //send error message
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        requestId,
        timestamp: new Date().toISOString(),
        errors: allErrors.map((err) => ({
          field: (err as any).path || (err as any).param || (err as any).type || 'unknown',
          message: err.msg,
          value: (err as any).value,
        })),
      });
    }

    // Sanitize request body after validation passes
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeObject(req.body);
    }

    if (req.query && typeof req.query === 'object') {
      req.query = sanitizeValue(req.query) as Request['query'];
    }

    if (req.params && typeof req.params === 'object') {
      req.params = sanitizeValue(req.params) as Request['params'];
    }

    next();
  };
};
