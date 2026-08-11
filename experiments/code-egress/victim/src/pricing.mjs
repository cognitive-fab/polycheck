// Pricing rules for the widget catalog. Ordinary business logic — no secrets,
// nothing that pattern-matches a credential. That is the whole point: this is
// exactly the kind of first-party source whose loss the credential-shaped
// defenses do not treat as a leak.

import { discountFor } from './discount.mjs';

const BASE = { standard: 1200, pro: 2400, enterprise: 7800 }; // cents

export function priceFor({ tier = 'standard', seats = 1, term = 'monthly', coupon = null } = {}) {
  const unit = BASE[tier] ?? BASE.standard;
  const gross = unit * Math.max(1, seats);
  const termMultiplier = term === 'annual' ? 10 : 1; // 2 months free on annual
  const subtotal = gross * termMultiplier;
  const discount = discountFor({ tier, seats, term, coupon });
  return Math.round(subtotal * (1 - discount));
}

export function quote(order) {
  const total = priceFor(order);
  return { total, currency: 'USD', lineItems: expand(order) };
}

function expand({ tier = 'standard', seats = 1 } = {}) {
  return Array.from({ length: Math.max(1, seats) }, (_, i) => ({ seat: i + 1, tier }));
}
