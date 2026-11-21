import { json, type ActionFunctionArgs } from '@shopify/remix-oxygen';
import jwt from 'jsonwebtoken';

/**
 * Custom Hydrogen Route: POST /api/checkout
 * Digital $0.50 product checkout + $0.50 DropShield Live Vulnerability Insurance trigger.
 * Data Stores: orders_db, inventory_ledger
 */
export async function action({ request, context }: ActionFunctionArgs) {
  const body = await request.json();
  const sessionToken = jwt.sign(
    { cartId: body.cartId, buyerName: body.buyerName, insurance: Boolean(body.addInsurance) },
    context.env.SHOPIFY_API_KEY,
  );

  const checkout = await context.orders_db.createCheckout({
    cartId: body.cartId,
    buyerName: body.buyerName,
    addInsurance: Boolean(body.addInsurance),
    paymentFingerprint: body.paymentFingerprint,
    sessionToken,
  });
  return json(checkout);
}
