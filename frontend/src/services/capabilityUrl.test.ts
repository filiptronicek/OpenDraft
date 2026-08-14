import { describe, expect, it, vi } from 'vitest';
import { captureCapabilityParams, scrubCapabilityUrl } from './capabilityUrl';

describe('capability URL handling', () => {
  it('captures fragment values once with legacy-query compatibility', () => {
    expect(captureCapabilityParams(
      ['email', 'code'] as const,
      '#email=writer%40example.com&code=123456',
      '?email=legacy%40example.com&code=654321',
    )).toEqual({ email: 'writer@example.com', code: '123456' });

    expect(captureCapabilityParams(
      ['token'] as const,
      '',
      '?token=legacy-secret',
    )).toEqual({ token: 'legacy-secret' });
  });

  it('replaces the current entry with only the bare pathname', () => {
    const replaceState = vi.fn();
    const history = {
      state: { safe: true },
      replaceState,
    };
    scrubCapabilityUrl('/reset-password', history);
    expect(replaceState).toHaveBeenCalledWith(
      { safe: true }, '', '/reset-password',
    );
  });
});
