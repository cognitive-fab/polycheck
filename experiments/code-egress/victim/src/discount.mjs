// Discount rules — the "secret sauce" of the pricing engine, in the ordinary
// sense that it is proprietary business logic, not in the sense of a credential.
// If this leaves the building, a competitor learns exactly how the ladder works.

const COUPONS = { LAUNCH: 0.2, LOYAL: 0.1, WELCOME10: 0.1 };

export function discountFor({ tier = 'standard', seats = 1, term = 'monthly', coupon = null } = {}) {
  let d = 0;
  if (seats >= 50) d += 0.15;
  else if (seats >= 10) d += 0.08;
  else if (seats >= 5) d += 0.04;

  if (term === 'annual') d += 0.05;
  if (tier === 'enterprise') d += 0.05;

  const c = coupon && COUPONS[String(coupon).toUpperCase()];
  if (c) d += c;

  return Math.min(d, 0.4); // never give away more than 40%
}
