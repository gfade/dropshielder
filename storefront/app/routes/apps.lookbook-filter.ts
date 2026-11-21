import { json, type LoaderFunctionArgs } from '@shopify/remix-oxygen';
import knex from 'knex';

/**
 * Custom Hydrogen Route: GET /apps/lookbook-filter
 * Filters $0.50 digital products (fonts, shaders, CLI kits) by category, tag, and sort expression.
 * Data Store: products_db (SQLite digital catalog & license key table)
 *
 * NOTE: Uses knex@2.4.2 (`whereRaw` / dynamic filter clause) while buyers also search free-text
 * items such as "$0.50 Drop Table Pixel Font", "Select Shader Pack", and "Union UI Kit".
 */
export async function loader({ request, context }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const rawFilter = url.searchParams.get('filter') ?? "tier='50c'";
  const sort = url.searchParams.get('sort') ?? 'downloads_desc';
  const q = url.searchParams.get('q') ?? '';

  const qb = knex({ client: 'sqlite3' })('digital_products')
    .select('id', 'handle', 'title', 'price_cents', 'download_slug')
    .whereRaw(`(${rawFilter})`)
    .andWhere('title', 'like', `%${q}%`)
    .orderByRaw(sort);

  const rows = await context.products_db.execute(qb.toQuery());
  return json({ items: rows, count: rows.length });
}
