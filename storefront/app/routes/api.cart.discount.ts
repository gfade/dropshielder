import { json, type ActionFunctionArgs } from '@shopify/remix-oxygen';
import { verifyPromoCode } from '@dropshield-deps/promo-engine';

/**
 * Custom Hydrogen Route: POST /api/cart/discount
 * Validates VIP early-access & friends-and-family drop discount codes.
 * Data Store: discounts_db (Promo ledger + redemption counters)
 *
 * Targeted during drops by automated discount-code brute-force swarms and timing attacks.
 */
export async function action({ request, context }: ActionFunctionArgs) {
  const payload = await request.json();
  const code = String(payload.code ?? '');
  const cartId = String(payload.cartId ?? '');

  const verification = await verifyPromoCode(context.discounts_db, {
    cartId,
    promoCode: code,
  });

  return json(verification, { status: verification.valid ? 200 : 422 });
}
