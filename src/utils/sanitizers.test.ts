import {
  sanitizeHtml,
  sanitizeObject,
  isSafeRedirectUrl,
  sanitizeFileName,
} from './sanitizers';

describe('sanitizeHtml', () => {
  it('removes script tags and their content', () => {
    expect(sanitizeHtml('<script>alert(1)</script>hello')).toBe('hello');
  });

  it('strips event handler attributes', () => {
    expect(sanitizeHtml('<img src="x" onerror="alert(1)">')).toBe('<img src="x">');
  });

  it('removes iframe, object, and embed tags', () => {
    expect(sanitizeHtml('<iframe src="evil.com"></iframe>hi')).toBe('hi');
    expect(sanitizeHtml('<object data="evil"></object>')).toBe('');
    expect(sanitizeHtml('<embed src="evil">')).toBe('');
  });

  it('neutralizes javascript: URLs', () => {
    expect(sanitizeHtml('<a href="javascript:alert(1)">click</a>')).toBe('<a>click</a>');
  });

  it('preserves plain text and safe HTML', () => {
    expect(sanitizeHtml('plain text')).toBe('plain text');
    expect(sanitizeHtml('<b>bold</b>')).toBe('<b>bold</b>');
  });

  it('handles empty and non-string input', () => {
    expect(sanitizeHtml('')).toBe('');
    expect(sanitizeHtml('   ')).toBe('');
  });
});

describe('sanitizeObject', () => {
  it('sanitizes nested string values', () => {
    const input = {
      name: '<script>alert(1)</script>Joe',
      nested: { bio: '<img src=x onerror=alert(1)>' },
    };
    const result = sanitizeObject(input);
    expect(result.name).toBe('Joe');
    expect(result.nested.bio).toBe('<img src="x">');
  });

  it('sanitizes string elements inside arrays', () => {
    const result = sanitizeObject({ tags: ['<script>x</script>', 'ok'] });
    expect(result.tags).toEqual(['', 'ok']);
  });

  it('leaves non-string primitives untouched', () => {
    const result = sanitizeObject({ n: 42, b: true, x: null });
    expect(result).toEqual({ n: 42, b: true, x: null });
  });

  it('returns non-object input unchanged', () => {
    expect(sanitizeObject('str')).toBe('str');
    expect(sanitizeObject(null)).toBe(null);
  });
});

describe('isSafeRedirectUrl', () => {
  it('accepts http and https URLs', () => {
    expect(isSafeRedirectUrl('https://example.com/cb')).toBe(true);
    expect(isSafeRedirectUrl('http://example.com/cb')).toBe(true);
  });

  it('rejects non-http protocols', () => {
    expect(isSafeRedirectUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeRedirectUrl('file:///etc/passwd')).toBe(false);
  });

  it('respects allowed domains when provided', () => {
    expect(isSafeRedirectUrl('https://app.deepiri.io/cb', ['app.deepiri.io'])).toBe(true);
    expect(isSafeRedirectUrl('https://evil.com/cb', ['app.deepiri.io'])).toBe(false);
  });

  it('rejects invalid URLs', () => {
    expect(isSafeRedirectUrl('not a url')).toBe(false);
    expect(isSafeRedirectUrl('')).toBe(false);
  });
});

describe('sanitizeFileName', () => {
  it('removes path traversal attempts', () => {
    expect(sanitizeFileName('../../etc/passwd')).toBe('etcpasswd');
    expect(sanitizeFileName('..\\..\\win')).toBe('win');
  });

  it('removes leading dots and null bytes', () => {
    expect(sanitizeFileName('..hidden')).toBe('hidden');
    expect(sanitizeFileName('evil\x00.txt')).toBe('evil.txt');
  });

  it('trims surrounding whitespace', () => {
    expect(sanitizeFileName('  report.pdf  ')).toBe('report.pdf');
  });
});
