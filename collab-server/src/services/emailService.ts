import * as nodemailer from 'nodemailer';
import * as crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { getDB } from '../db';
import { config } from '../config';

let transporter: nodemailer.Transporter | null = null;

const HTML_ESCAPE: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => HTML_ESCAPE[character]);
}

function getTransporter(): nodemailer.Transporter | null {
  if (!config.smtpHost) return null;
  if (transporter) return transporter;

  transporter = nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpPort === 465,
    auth: config.smtpUser ? { user: config.smtpUser, pass: config.smtpPass || '' } : undefined,
  });

  return transporter;
}

export async function createVerificationCode(userId: string): Promise<string> {
  const db = getDB();
  const code = String(crypto.randomInt(100000, 1_000_000));
  const id = uuidv4();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000).toISOString(); // 15 minutes

  // Invalidate any existing codes for this user
  await db.run('UPDATE email_verifications SET used = 1 WHERE user_id = ? AND used = 0', [userId]);

  await db.run(
    `INSERT INTO email_verifications (id, user_id, code, expires_at, used, created_at)
     VALUES (?, ?, ?, ?, 0, ?)`,
    [id, userId, code, expiresAt, now.toISOString()],
  );

  return code;
}

export async function validateVerificationCode(userId: string, code: string): Promise<boolean> {
  const db = getDB();
  const now = new Date().toISOString();

  const row = await db.get<{ id: string }>(
    `SELECT id FROM email_verifications
     WHERE user_id = ? AND code = ? AND used = 0 AND expires_at > ?
     ORDER BY created_at DESC LIMIT 1`,
    [userId, code, now],
  );

  if (!row) return false;

  const claimed = await db.run(
    'UPDATE email_verifications SET used = 1 WHERE id = ? AND used = 0',
    [row.id],
  );
  return claimed.changes === 1;
}

export async function sendVerificationEmail(email: string, code: string): Promise<void> {
  // Keep verification capabilities in the fragment so proxies never log them.
  const magicLink = `${config.appUrl}/verify#email=${encodeURIComponent(email)}&code=${encodeURIComponent(code)}`;

  const transport = getTransporter();
  if (!transport) {
    console.log(`[Email] SMTP not configured. Verification code for ${email}: ${code}`);
    console.log(`[Email] Magic link: ${magicLink}`);
    return;
  }

  await transport.sendMail({
    from: config.smtpFrom,
    to: email,
    subject: 'OpenDraft - Verify your email',
    text: `Your verification code is: ${code}\n\nOr click this link to activate your account:\n${magicLink}\n\nBoth expire in 15 minutes.`,
    html: `
      <div style="font-family: sans-serif; max-width: 440px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">OpenDraft Email Verification</h2>
        <p>Activate your account by clicking the link below:</p>
        <p style="text-align: center; margin: 20px 0;">
          <a href="${escapeHtml(magicLink)}" style="display: inline-block; background: #4a6fa5; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600;">Activate account</a>
        </p>
        <p>Or enter this verification code manually:</p>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; padding: 20px; background: #f5f5f5; border-radius: 8px; margin: 16px 0;">
          ${escapeHtml(code)}
        </div>
        <p style="color: #666; font-size: 13px;">Both the link and code expire in 15 minutes.</p>
      </div>
    `,
  });
}

export async function sendNewDeviceCode(
  email: string,
  code: string,
  deviceName: string,
  ipAddress: string | null,
): Promise<void> {
  const transport = getTransporter();
  const ipLine = ipAddress ? `\nIP address: ${ipAddress}` : '';
  if (!transport) {
    console.log(`[Email] SMTP not configured. New-device code for ${email} on "${deviceName}": ${code}`);
    return;
  }

  await transport.sendMail({
    from: config.smtpFrom,
    to: email,
    subject: 'OpenDraft - New sign-in attempt',
    text:
      `We noticed a sign-in attempt to your OpenDraft account from a new device:\n\n` +
      `Device: ${deviceName}${ipLine}\n\n` +
      `Enter this 6-digit verification code to confirm it was you:\n\n${code}\n\n` +
      `This code expires in 15 minutes.\n\n` +
      `If you did not try to sign in, please change your password immediately and ` +
      `review the active devices in OpenDraft Settings.`,
    html: `
      <div style="font-family: sans-serif; max-width: 440px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">New sign-in attempt</h2>
        <p>We noticed a sign-in attempt to your OpenDraft account from a new device:</p>
        <div style="background: #f5f5f5; border-radius: 6px; padding: 12px 16px; margin: 12px 0;">
          <div><strong>Device:</strong> ${escapeHtml(deviceName)}</div>
          ${ipAddress ? `<div><strong>IP:</strong> ${escapeHtml(ipAddress)}</div>` : ''}
        </div>
        <p>Enter this 6-digit verification code to confirm it was you:</p>
        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; padding: 20px; background: #f5f5f5; border-radius: 8px; margin: 16px 0;">
          ${escapeHtml(code)}
        </div>
        <p style="color: #666; font-size: 13px;">The code expires in 15 minutes.</p>
        <p style="color: #b00; font-size: 13px;">
          If this wasn't you, change your password immediately and review your devices
          in OpenDraft → Settings → Account.
        </p>
      </div>
    `,
  });
}

export async function sendNewDeviceNotice(
  email: string,
  deviceName: string,
  ipAddress: string | null,
): Promise<void> {
  const transport = getTransporter();
  const ipLine = ipAddress ? `\nIP address: ${ipAddress}` : '';
  if (!transport) {
    console.log(`[Email] SMTP not configured. New-device notice for ${email} on "${deviceName}"`);
    return;
  }

  await transport.sendMail({
    from: config.smtpFrom,
    to: email,
    subject: 'OpenDraft - A new device just signed in',
    text:
      `A new device just signed in to your OpenDraft account:\n\n` +
      `Device: ${deviceName}${ipLine}\n\n` +
      `If this was you, you can ignore this email.\n\n` +
      `If it wasn't, change your password immediately and revoke the device from ` +
      `OpenDraft Settings → Account → Devices. You can also enable two-factor ` +
      `verification there to require an emailed code on every new device.`,
    html: `
      <div style="font-family: sans-serif; max-width: 440px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">A new device just signed in</h2>
        <p>A new device just signed in to your OpenDraft account:</p>
        <div style="background: #f5f5f5; border-radius: 6px; padding: 12px 16px; margin: 12px 0;">
          <div><strong>Device:</strong> ${escapeHtml(deviceName)}</div>
          ${ipAddress ? `<div><strong>IP:</strong> ${escapeHtml(ipAddress)}</div>` : ''}
        </div>
        <p>If this was you, you can ignore this email.</p>
        <p style="color: #b00;">
          If it wasn't, change your password immediately and revoke the device
          from OpenDraft → Settings → Account → Devices. You can also enable
          two-factor verification there.
        </p>
      </div>
    `,
  });
}

export async function sendPasswordResetEmail(
  email: string,
  token: string,
  ipAddress: string | null,
): Promise<void> {
  // The link carries only the opaque token — the server looks the user up by
  // matching it against stored hashes. No email is in the URL.
  const resetLink = `${config.appUrl}/reset-password#token=${encodeURIComponent(token)}`;
  const ipLine = ipAddress ? `\nRequested from IP: ${ipAddress}` : '';

  const transport = getTransporter();
  if (!transport) {
    console.log(`[Email] SMTP not configured. Password reset link for ${email}: ${resetLink}`);
    return;
  }

  await transport.sendMail({
    from: config.smtpFrom,
    to: email,
    subject: 'OpenDraft - Reset your password',
    text:
      `Someone requested a password reset for your OpenDraft account.${ipLine}\n\n` +
      `If this was you, click the link below to choose a new password. The link expires in 30 minutes:\n\n${resetLink}\n\n` +
      `If you did not request this, you can safely ignore this email — your password will not change.`,
    html: `
      <div style="font-family: sans-serif; max-width: 440px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #333;">Reset your OpenDraft password</h2>
        <p>Someone requested a password reset for your OpenDraft account.</p>
        ${ipAddress ? `<p style="color: #666; font-size: 13px;">Requested from IP: ${escapeHtml(ipAddress)}</p>` : ''}
        <p>If this was you, click the button below to choose a new password:</p>
        <p style="text-align: center; margin: 20px 0;">
          <a href="${escapeHtml(resetLink)}" style="display: inline-block; background: #4a6fa5; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600;">Reset password</a>
        </p>
        <p style="color: #666; font-size: 13px;">Or copy this link into your browser:<br><span style="word-break: break-all;">${escapeHtml(resetLink)}</span></p>
        <p style="color: #666; font-size: 13px;">The link expires in 30 minutes.</p>
        <p style="color: #b00; font-size: 13px;">
          If you did not request this, you can safely ignore this email — your
          password will not change.
        </p>
      </div>
    `,
  });
}

export async function sendPasswordChangedNotice(email: string, deviceName: string): Promise<void> {
  const transport = getTransporter();
  if (!transport) {
    console.log(`[Email] SMTP not configured. Password-changed notice for ${email} ("${deviceName}")`);
    return;
  }
  await transport.sendMail({
    from: config.smtpFrom,
    to: email,
    subject: 'OpenDraft - Your password was changed',
    text:
      `Your OpenDraft password was just changed from "${deviceName}".\n\n` +
      `If this wasn't you, please reset your password immediately and contact support.`,
    html: `
      <div style="font-family: sans-serif; max-width: 440px; margin: 0 auto; padding: 20px;">
        <h2>Your OpenDraft password was changed</h2>
        <p>Your password was just changed from <strong>${escapeHtml(deviceName)}</strong>.</p>
        <p style="color: #b00;">If this wasn't you, reset your password immediately and contact support.</p>
      </div>
    `,
  });
}

export async function sendAccountDeletedNotice(email: string): Promise<void> {
  const transport = getTransporter();
  if (!transport) {
    console.log('[Email] SMTP not configured. Account-deleted notice not sent.');
    return;
  }
  await transport.sendMail({
    from: config.smtpFrom,
    to: email,
    subject: 'OpenDraft - Your account was deleted',
    text:
      `Your active OpenDraft account (${email}), credentials, and collaboration records were deleted at your request. ` +
      `The server also attempts to remove your active cloud project storage.\n\n` +
      `Administrator-managed Git mirrors, filesystem snapshots, and off-site backups may persist until their retention period ends or an administrator removes them.\n\n` +
      `If you did not request this, please contact support immediately — the active account cannot be recovered after deletion.`,
    html: `
      <div style="font-family: sans-serif; max-width: 440px; margin: 0 auto; padding: 20px;">
        <h2>Your OpenDraft account was deleted</h2>
        <p>Your active account, credentials, and collaboration records were deleted. The server also attempts to remove your active cloud project storage.</p>
        <p>Administrator-managed Git mirrors, filesystem snapshots, and off-site backups may persist until their retention period ends or an administrator removes them.</p>
        <p style="color: #b00;">
          If you did not request this, contact support immediately —
          the active account cannot be recovered after deletion.
        </p>
      </div>
    `,
  });
}
