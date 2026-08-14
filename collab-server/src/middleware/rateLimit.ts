import rateLimit from 'express-rate-limit';
import { config } from '../config';

export const standardLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: config.rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

export const strictLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

export const veryStrictLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

// A browser OIDC login crosses three endpoints. Keep separate stores so starts
// cannot consume the callback or handoff-exchange quota, and so ordinary auth
// traffic does not make a partially completed provider flow fail mid-way.
export const oidcStartLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts, please try again later' },
});

export const oidcCallbackLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many sign-in callbacks, please try again later' },
});

export const oidcExchangeLimiter = rateLimit({
  windowMs: config.rateLimitWindowMs,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many sign-in exchanges, please try again later' },
});
