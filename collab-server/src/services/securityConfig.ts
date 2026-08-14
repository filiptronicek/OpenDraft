const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['0', 'false', 'no', 'off']);

/** Parse security-sensitive feature switches without treating typos as true. */
export function parseSecurityBoolean(
  name: string,
  value: string | undefined,
  defaultValue: boolean,
): boolean {
  if (value === undefined) return defaultValue;
  const normalized = value.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  throw new Error(
    `${name} must be one of: true, false, 1, 0, yes, no, on, off`,
  );
}

export function registrationSetting(environment: NodeJS.ProcessEnv): boolean {
  if (environment.LOCAL_REGISTRATION_ENABLED !== undefined) {
    return parseSecurityBoolean('LOCAL_REGISTRATION_ENABLED', environment.LOCAL_REGISTRATION_ENABLED, true);
  }
  return parseSecurityBoolean('REGISTRATION_ENABLED', environment.REGISTRATION_ENABLED, true);
}
