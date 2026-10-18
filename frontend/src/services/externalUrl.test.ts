import { describe, expect, it } from 'vitest';
import { safeExternalHttpUrl } from './externalUrl';

describe('external URL safety', () => {
  it('accepts only absolute HTTP(S) URLs without credentials', () => {
    expect(safeExternalHttpUrl('https://example.com/article?q=1')).toBe(
      'https://example.com/article?q=1',
    );
    expect(safeExternalHttpUrl('http://example.com')).toBe('http://example.com/');

    for (const value of [
      '/relative',
      'javascript:alert(1)',
      'data:text/html,hello',
      'ftp://example.com/file',
      'https://user@example.com/',
      'https://user:password@example.com/',
    ]) {
      expect(safeExternalHttpUrl(value)).toBeNull();
    }
  });
});
