import type { IncomingMessage } from 'http';

type TrustProxy = (address: string, index?: number) => boolean;
type ProxyAddress = {
  (request: IncomingMessage, trust: TrustProxy): string;
  compile(value: string | string[]): TrustProxy;
};

// Express already installs proxy-addr. It is also declared as a direct runtime
// dependency because this module uses it for WebSocket upgrade requests.
const proxyAddress = require('proxy-addr') as ProxyAddress;

export function compileTrustedProxy(entries: string[]): TrustProxy {
  return proxyAddress.compile(entries.length > 0 ? entries : ['loopback']);
}

/**
 * Resolve X-Forwarded-For only while walking through explicitly trusted proxy
 * hops. A client connected directly from an untrusted address cannot spoof it.
 */
export function resolveClientIp(
  request: IncomingMessage,
  trust: TrustProxy,
): string {
  const remoteAddress = request.socket.remoteAddress;
  if (!remoteAddress) return 'unknown';
  try {
    return proxyAddress(request, trust) || remoteAddress;
  } catch {
    return remoteAddress;
  }
}
