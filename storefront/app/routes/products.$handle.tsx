import { json, type LoaderFunctionArgs } from '@shopify/remix-oxygen';
import qs from 'qs';
import { minimatch } from 'minimatch';

/**
 * Hydrogen Storefront Route: GET /products/:handle & GET /api/catalog/search
 * Standard buyer free-text product search & PDP loader.
 * Data Store: products_db (parameterized read-only catalog)
 *
 * IMPORTANT FOR EXPOSURE MAPPING & HARD NEGATIVES:
 *  - Buyers frequently search free text containing SQL keywords ("Drop Table Tee",
 *    "Union Heavyweight Hoodie", "Select Cargo Pant") or names with apostrophes ("O'Brien").
 *  - Notice `@dropshield-deps/xml-invoice-parser` is in `package.json` but is NEVER imported
 *    by any live route! Asset-graph hops must verify actual AST import paths, not just package.json names.
 */
export async function loader({ request, params, context }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const parsed = qs.parse(url.search, { ignoreQueryPrefix: true });
  const query = String(parsed.q ?? params.handle ?? '');
  const isDropTag = minimatch(query, 'drop-*');

  const products = await context.products_db.parameterizedCatalogSearch({
    query,
    isDropTag,
  });

  return json({ products });
}
