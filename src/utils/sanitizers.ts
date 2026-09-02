import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

/**
 * Input Sanitization Utilities
 * Cleans and sanitizes user inputs to prevent XSS and other injection attacks
 */

let sanitizer: ReturnType<typeof createDOMPurify> | null = null;

const getSanitizer = (): ReturnType<typeof createDOMPurify> => {
  if (!sanitizer) {
    const window = new JSDOM('').window;
    sanitizer = createDOMPurify(window);
  }
  return sanitizer;
};

/**
 * Sanitize HTML - Remove dangerous tags and attributes
 * Prevents XSS attacks
 */
export const sanitizeHtml = (input: string): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // A string with no '<' cannot open an HTML tag, so there is nothing for DOMPurify
  // to strip. Running it anyway rewrites content that only looks like markup
  // (e.g. "a < b" -> "a &lt; b") and can drop text after a stray '<'. Skip it.
  if (!input.includes('<')) {
    return input.trim();
  }

  return getSanitizer()
    .sanitize(input, {
      USE_PROFILES: { html: true },
      FORBID_TAGS: ['iframe', 'object', 'embed'],
    })
    .trim();
};

/**
 * Sanitize all fields in an object
 * Applies HTML sanitization to string fields
 */
// Secret / credential fields must never be run through an HTML sanitizer: DOMPurify
// can alter or truncate a value that happens to contain '<', silently changing the
// password/token before it is hashed or compared.
const SANITIZE_SKIP_KEYS = new Set([
  'password',
  'currentpassword',
  'newpassword',
  'confirmpassword',
  'token',
  'refreshtoken',
  'accesstoken',
  'code',
  'clientsecret',
  'client_secret',
  'secret',
]);

export const sanitizeObject = (obj: any): any => {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const sanitized: any = {};

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const value = obj[key];

      if (typeof value === 'string') {
        // Sanitize string values (except credential fields — see SANITIZE_SKIP_KEYS)
        sanitized[key] = SANITIZE_SKIP_KEYS.has(key.toLowerCase())
          ? value
          : sanitizeHtml(value);
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        // Recursively sanitize nested objects
        sanitized[key] = sanitizeObject(value);
      } else if (Array.isArray(value)) {
        // Sanitize array elements
        sanitized[key] = value.map(item => 
          typeof item === 'string' ? sanitizeHtml(item) : item
        );
      } else {
        sanitized[key] = value;
      }
    }
  }

  return sanitized;
};

/**
 * Prevent Open Redirect attacks
 * Validates that redirect URLs are safe
 */
export const isSafeRedirectUrl = (url: string, allowedDomains: string[] = []): boolean => {
  if (!url || typeof url !== 'string') {
    return false;
  }

  try {
    const urlObj = new URL(url);

    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return false;
    }

    // If allowed domains specified, check if URL is in list
    if (allowedDomains.length > 0) {
      return allowedDomains.some(domain => urlObj.hostname === domain);
    }

    return true;
  } catch (error) {
    // Invalid URL
    return false;
  }
};

/**
 * Sanitize file names to prevent path traversal attacks
 */
export const sanitizeFileName = (fileName: string): string => {
  if (!fileName || typeof fileName !== 'string') {
    return '';
  }

  // Remove path separators and relative path attempts
  return fileName
    .replace(/\.\./g, '')           // Remove ..
    .replace(/[\/\\]/g, '')         // Remove slashes
    .replace(/^\.+/, '')            // Remove leading dots
    .replace(/\x00/g, '')           // Remove null bytes
    .trim();
};
