/** Return a normalized URL only when it is safe to expose as an external link. */
export function safeExternalHttpUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (
      (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
      || parsed.username
      || parsed.password
    ) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}
