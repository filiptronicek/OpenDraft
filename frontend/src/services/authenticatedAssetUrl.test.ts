import { describe, expect, it, vi } from 'vitest';
import { AuthenticatedAssetUrlCache } from './authenticatedAssetUrl';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('AuthenticatedAssetUrlCache', () => {
  it.each([
    'data:image/png;base64,AA==',
    'blob:https://example.test/direct',
    'asset://localhost/path/to/image.png',
    'http://asset.localhost/path/to/image.png',
  ])('returns direct URL %s without fetching or revoking it', async (sourceUrl) => {
    const fetchBlob = vi.fn(async () => new Blob(['unexpected']));
    const revokeObjectUrl = vi.fn();
    const cache = new AuthenticatedAssetUrlCache(
      fetchBlob,
      () => 'blob:unexpected',
      revokeObjectUrl,
    );

    const lease = cache.acquire('user-a', sourceUrl);
    await expect(lease.url).resolves.toBe(sourceUrl);
    lease.release();

    expect(fetchBlob).not.toHaveBeenCalled();
    expect(revokeObjectUrl).not.toHaveBeenCalled();
  });

  it('shares an in-flight fetch between leases for the same user and URL', async () => {
    const pending = deferred<Blob>();
    const fetchBlob = vi.fn(() => pending.promise);
    const createObjectUrl = vi.fn(() => 'blob:shared');
    const revokeObjectUrl = vi.fn();
    const cache = new AuthenticatedAssetUrlCache(fetchBlob, createObjectUrl, revokeObjectUrl);

    const first = cache.acquire('user-a', 'https://example.test/asset');
    const second = cache.acquire('user-a', 'https://example.test/asset');
    await Promise.resolve();

    expect(fetchBlob).toHaveBeenCalledTimes(1);
    pending.resolve(new Blob(['asset']));
    await expect(Promise.all([first.url, second.url])).resolves.toEqual([
      'blob:shared',
      'blob:shared',
    ]);

    first.release();
    expect(revokeObjectUrl).not.toHaveBeenCalled();
    second.release();
  });

  it('isolates cache entries for different authenticated users', async () => {
    const fetchBlob = vi.fn(async () => new Blob(['asset']));
    const createObjectUrl = vi
      .fn<(blob: Blob) => string>()
      .mockReturnValueOnce('blob:user-a')
      .mockReturnValueOnce('blob:user-b');
    const revokeObjectUrl = vi.fn();
    const cache = new AuthenticatedAssetUrlCache(fetchBlob, createObjectUrl, revokeObjectUrl);

    const first = cache.acquire('user-a', 'https://example.test/asset');
    const second = cache.acquire('user-b', 'https://example.test/asset');

    await expect(first.url).resolves.toBe('blob:user-a');
    await expect(second.url).resolves.toBe('blob:user-b');
    expect(fetchBlob).toHaveBeenCalledTimes(2);

    first.release();
    second.release();
  });

  it('revokes the object URL only when the final lease is released', async () => {
    const revokeObjectUrl = vi.fn();
    const cache = new AuthenticatedAssetUrlCache(
      async () => new Blob(['asset']),
      () => 'blob:ready',
      revokeObjectUrl,
    );
    const first = cache.acquire('user-a', 'https://example.test/asset');
    const second = cache.acquire('user-a', 'https://example.test/asset');
    await first.url;

    first.release();
    first.release();
    expect(revokeObjectUrl).not.toHaveBeenCalled();

    second.release();
    expect(revokeObjectUrl).toHaveBeenCalledOnce();
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:ready');
  });

  it('revokes an object URL created after every pending lease was released', async () => {
    const pending = deferred<Blob>();
    const fetchBlob = vi.fn(() => pending.promise);
    const revokeObjectUrl = vi.fn();
    const cache = new AuthenticatedAssetUrlCache(
      fetchBlob,
      () => 'blob:late',
      revokeObjectUrl,
    );
    const lease = cache.acquire('user-a', 'https://example.test/asset');

    lease.release();
    pending.resolve(new Blob(['asset']));
    await expect(lease.url).resolves.toBe('blob:late');

    expect(revokeObjectUrl).toHaveBeenCalledOnce();
    expect(revokeObjectUrl).toHaveBeenCalledWith('blob:late');

    const nextLease = cache.acquire('user-a', 'https://example.test/asset');
    await expect(nextLease.url).resolves.toBe('blob:late');
    expect(fetchBlob).toHaveBeenCalledTimes(2);
    nextLease.release();
  });
});
