import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcryptjs';
import {
  getDB,
  type DBAdapter,
  type ExternalIdentityRow,
  type UserRow,
} from '../db';
import { config } from '../config';

export interface ExternalIdentityInput {
  issuer: string;
  subject: string;
  email: string;
  displayName: string;
}

export class ExternalIdentityEmailConflictError extends Error {
  constructor() {
    super('An account with this email already exists and must be linked while signed in');
    this.name = 'ExternalIdentityEmailConflictError';
  }
}

export class ExternalIdentityAlreadyLinkedError extends Error {
  constructor() {
    super('This external identity is already linked to another account');
    this.name = 'ExternalIdentityAlreadyLinkedError';
  }
}

export class ExternalIdentityEmailMismatchError extends Error {
  constructor() {
    super('The identity provider email does not match the signed-in account');
    this.name = 'ExternalIdentityEmailMismatchError';
  }
}

// Precomputed once so unknown-email login attempts perform the same password
// KDF work as wrong-password attempts without creating attacker-controlled cost.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('OpenDraft invalid login sentinel 9Z', config.bcryptRounds);

const USER_SELECT = `SELECT users.*,
  (SELECT COUNT(*) FROM external_identities WHERE external_identities.user_id = users.id)
    AS external_identity_count
  FROM users`;

export async function createUser(email: string, password: string, displayName: string): Promise<UserRow> {
  const db = getDB();
  const id = uuidv4();
  const now = new Date().toISOString();
  const passwordHash = bcrypt.hashSync(password, config.bcryptRounds);

  await db.run(
    `INSERT INTO users (id, email, email_verified, password_hash, display_name, created_at, updated_at)
     VALUES (?, ?, 0, ?, ?, ?, ?)`,
    [id, email.toLowerCase(), passwordHash, displayName, now, now],
  );

  return (await findUserById(id))!;
}

export async function findUserByEmail(email: string): Promise<UserRow | null> {
  return findUserByEmailWithDB(getDB(), email);
}

async function findUserByEmailWithDB(db: DBAdapter, email: string): Promise<UserRow | null> {
  const row = await db.get<UserRow>(`${USER_SELECT} WHERE users.email = ?`, [email.toLowerCase()]);
  return row ?? null;
}

export async function findUserById(id: string): Promise<UserRow | null> {
  return findUserByIdWithDB(getDB(), id);
}

async function findUserByIdWithDB(db: DBAdapter, id: string): Promise<UserRow | null> {
  const row = await db.get<UserRow>(`${USER_SELECT} WHERE users.id = ?`, [id]);
  return row ?? null;
}

export async function findOrCreateGoogleUser(
  googleId: string,
  email: string,
  displayName: string,
  db: DBAdapter = getDB(),
): Promise<UserRow> {

  // Check if user exists by google_id
  const existing = await db.get<UserRow>(`${USER_SELECT} WHERE users.google_id = ?`, [googleId]);
  if (existing) return existing;

  // Check if user exists by email (link accounts)
  const emailUser = await findUserByEmailWithDB(db, email);
  if (emailUser) {
    // Never let a second provider claim an OIDC identity by matching email.
    // Provider linking must prove control of the already signed-in account.
    if (Number(emailUser.external_identity_count || 0) > 0 || !emailUser.password_hash) {
      throw new ExternalIdentityEmailConflictError();
    }
    const now = new Date().toISOString();
    await db.run(
      'UPDATE users SET google_id = ?, email_verified = 1, updated_at = ? WHERE id = ?',
      [googleId, now, emailUser.id],
    );
    return (await findUserByIdWithDB(db, emailUser.id))!;
  }

  // Create new user
  const id = uuidv4();
  const now = new Date().toISOString();
  await db.run(
    `INSERT INTO users (id, email, email_verified, google_id, display_name, created_at, updated_at)
     VALUES (?, ?, 1, ?, ?, ?, ?)`,
    [id, email.toLowerCase(), googleId, displayName, now, now],
  );

  return (await findUserByIdWithDB(db, id))!;
}

async function findExternalIdentity(
  issuer: string,
  subject: string,
  db: DBAdapter = getDB(),
): Promise<ExternalIdentityRow | null> {
  const identity = await db.get<ExternalIdentityRow>(
    'SELECT * FROM external_identities WHERE issuer = ? AND subject = ?',
    [issuer, subject],
  );
  return identity ?? null;
}

async function existingExternalUser(
  issuer: string,
  subject: string,
  db: DBAdapter = getDB(),
): Promise<UserRow | null> {
  const identity = await findExternalIdentity(issuer, subject, db);
  if (!identity) return null;
  return findUserByIdWithDB(db, identity.user_id);
}

/**
 * Resolve an OIDC principal without ever using email as an account-link key.
 * A matching email is an explicit conflict and can only be resolved by the
 * authenticated linking flow.
 */
export async function findOrCreateExternalUser(
  input: ExternalIdentityInput,
  db: DBAdapter = getDB(),
): Promise<UserRow> {
  try {
    return await db.transaction(async (transaction) => {
      const existing = await existingExternalUser(
        input.issuer,
        input.subject,
        transaction,
      );
      if (existing) {
        const now = new Date().toISOString();
        await transaction.run(
          'UPDATE external_identities SET email = ?, updated_at = ? WHERE issuer = ? AND subject = ?',
          [input.email.toLowerCase(), now, input.issuer, input.subject],
        );
        return existing;
      }

      if (await findUserByEmailWithDB(transaction, input.email)) {
        throw new ExternalIdentityEmailConflictError();
      }

      const userId = uuidv4();
      const identityId = uuidv4();
      const now = new Date().toISOString();
      await transaction.run(
        `INSERT INTO users
          (id, email, email_verified, password_hash, display_name, created_at, updated_at)
         VALUES (?, ?, 1, NULL, ?, ?, ?)`,
        [userId, input.email.toLowerCase(), input.displayName, now, now],
      );
      await transaction.run(
        `INSERT INTO external_identities
          (id, issuer, subject, user_id, email, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          identityId,
          input.issuer,
          input.subject,
          userId,
          input.email.toLowerCase(),
          now,
          now,
        ],
      );
      return (await findUserByIdWithDB(transaction, userId))!;
    });
  } catch (error) {
    if (error instanceof ExternalIdentityEmailConflictError) throw error;
    // Unique constraints serialize concurrent callbacks. Once the failed
    // transaction rolls back, resolve the principal that won the race.
    const raced = await existingExternalUser(input.issuer, input.subject, db);
    if (raced) return raced;
    if (await findUserByEmailWithDB(db, input.email)) throw new ExternalIdentityEmailConflictError();
    throw error;
  }
}

/** Explicitly link a verified provider principal to an authenticated user. */
export async function linkExternalIdentity(
  userId: string,
  input: ExternalIdentityInput,
  db: DBAdapter = getDB(),
): Promise<UserRow> {
  try {
    return await db.transaction(async (transaction) => {
      const user = await findUserByIdWithDB(transaction, userId);
      if (!user) throw new Error('User not found');

      const existing = await findExternalIdentity(
        input.issuer,
        input.subject,
        transaction,
      );
      if (existing && existing.user_id !== userId) {
        throw new ExternalIdentityAlreadyLinkedError();
      }
      if (user.email.toLowerCase() !== input.email.toLowerCase()) {
        throw new ExternalIdentityEmailMismatchError();
      }

      const now = new Date().toISOString();
      if (existing) {
        await transaction.run(
          'UPDATE external_identities SET email = ?, updated_at = ? WHERE id = ?',
          [input.email.toLowerCase(), now, existing.id],
        );
      } else {
        await transaction.run(
          `INSERT INTO external_identities
            (id, issuer, subject, user_id, email, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [uuidv4(), input.issuer, input.subject, userId, input.email.toLowerCase(), now, now],
        );
      }
      if (!user.email_verified) {
        await transaction.run(
          'UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?',
          [now, userId],
        );
      }
      return (await findUserByIdWithDB(transaction, userId))!;
    });
  } catch (error) {
    if (
      error instanceof ExternalIdentityAlreadyLinkedError
      || error instanceof ExternalIdentityEmailMismatchError
      || (error instanceof Error && error.message === 'User not found')
    ) {
      throw error;
    }
    const raced = await findExternalIdentity(input.issuer, input.subject, db);
    if (!raced) throw error;
    if (raced.user_id !== userId) throw new ExternalIdentityAlreadyLinkedError();
    return (await findUserByIdWithDB(db, userId))!;
  }
}

export async function verifyPassword(user: UserRow | null, password: string): Promise<boolean> {
  const passwordHash = user?.password_hash || DUMMY_PASSWORD_HASH;
  return bcrypt.compareSync(password, passwordHash) && Boolean(user?.password_hash);
}

export async function setEmailVerified(userId: string): Promise<void> {
  const db = getDB();
  const now = new Date().toISOString();
  await db.run('UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?', [now, userId]);
}

export async function setTwoFactorEnabled(userId: string, enabled: boolean): Promise<void> {
  const db = getDB();
  const now = new Date().toISOString();
  await db.run(
    'UPDATE users SET two_factor_enabled = ?, updated_at = ? WHERE id = ?',
    [enabled ? 1 : 0, now, userId],
  );
}

export async function updatePassword(userId: string, newPassword: string): Promise<void> {
  const db = getDB();
  const now = new Date().toISOString();
  const passwordHash = bcrypt.hashSync(newPassword, config.bcryptRounds);
  await db.run(
    'UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?',
    [passwordHash, now, userId],
  );
}

/**
 * Delete a user and every record that references them.
 *
 * `users` is the parent of refresh_tokens, email_verifications, user_devices,
 * and device_challenges via ON DELETE CASCADE — but we explicitly delete the
 * children first so the same code path works on databases where cascades
 * weren't defined when the table was first created (older deployments).
 *
 * Invite rows are deleted and audit rows are anonymized because neither has a
 * foreign key to the user table.
 */
export async function deleteUser(
  userId: string,
  db: DBAdapter = getDB(),
  markDeletionMayHaveOccurred?: () => void,
): Promise<void> {
  await db.run('DELETE FROM collab_sessions WHERE created_by = ?', [userId]);
  await db.run('DELETE FROM external_identities WHERE user_id = ?', [userId]);
  await db.run('DELETE FROM password_resets WHERE user_id = ?', [userId]);
  await db.run('DELETE FROM device_challenges WHERE user_id = ?', [userId]);
  await db.run('DELETE FROM user_devices WHERE user_id = ?', [userId]);
  await db.run('DELETE FROM email_verifications WHERE user_id = ?', [userId]);
  await db.run('DELETE FROM refresh_tokens WHERE user_id = ?', [userId]);
  // Anonymise audit log so the deletion event is preserved without keeping PII.
  await db.run(
    "UPDATE audit_log SET user_id = NULL, detail = NULL WHERE user_id = ?",
    [userId],
  );
  markDeletionMayHaveOccurred?.();
  await db.run('DELETE FROM users WHERE id = ?', [userId]);
  // Owner-checked invite inserts that observed the user before DELETE finish
  // before this final deletion; later inserts cannot select an owner row.
  await db.run('DELETE FROM collab_sessions WHERE created_by = ?', [userId]);
}
