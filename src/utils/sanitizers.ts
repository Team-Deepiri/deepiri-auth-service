/**
 * Input Sanitization Utilities
 * Cleans and sanitizes user inputs to prevent XSS, SQL injection, and NoSQL injection
 */

/**
 * Sanitize HTML - Remove dangerous tags and attributes
 * Prevents XSS attacks
 */
export const sanitizeHtml = (input: string): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Remove script tags and content
  let sanitized = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

  // Remove event handlers (onclick, onerror, etc.)
  sanitized = sanitized.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
  sanitized = sanitized.replace(/\s*on\w+\s*=\s*[^\s>]*/gi, '');

  // Remove iframe, object, embed tags
  sanitized = sanitized.replace(/<(iframe|object|embed)[^>]*>/gi, '');

  // Remove potentially dangerous HTML attributes
  sanitized = sanitized.replace(/src\s*=\s*["']javascript:[^"']*["']/gi, '');

  return sanitized.trim();
};

/**
 * Prevent SQL Injection - Escape SQL special characters
 * Note: Always use parameterized queries instead of string concatenation
 * This is a fallback defense layer
 */
export const escapeSqlString = (input: string): string => {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // Escape SQL special characters
  return input
    .replace(/\\/g, '\\\\')    // Backslash
    .replace(/'/g, "''")       // Single quote
    .replace(/"/g, '\\"')      // Double quote
    .replace(/\x00/g, '\\0')   // Null byte
    .replace(/\n/g, '\\n')     // Newline
    .replace(/\r/g, '\\r');    // Carriage return
};

/**
 * Prevent NoSQL Injection - Remove dangerous operators
 * Prevents MongoDB operators like {$ne: null} being used maliciously
 */
export const sanitizeNoSqlInput = (input: any): any => {
  if (typeof input === 'string') {
    // Reject strings that look like operators
    if (input.startsWith('$') || input.startsWith('{') || input.startsWith('[')) {
      return '';
    }
    return input;
  }

  if (typeof input === 'object' && input !== null) {
    // If it's an object with $ keys, it's likely an operator - reject it
    for (const key in input) {
      if (key.startsWith('$')) {
        return {};
      }
    }
    return input;
  }

  return input;
};

/**
 * Sanitize all fields in an object
 * Applies HTML sanitization to string fields
 */
export const sanitizeObject = (obj: any): any => {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const sanitized: any = {};

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const value = obj[key];

      if (typeof value === 'string') {
        // Sanitize string values
        sanitized[key] = sanitizeHtml(value);
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
