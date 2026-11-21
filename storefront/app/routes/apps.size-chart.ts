import { json, type LoaderFunctionArgs } from '@shopify/remix-oxygen';
import send from 'send';
import pathToRegexp from 'path-to-regexp';

/**
 * Custom Hydrogen Route: GET /apps/size-chart
 * Serves digital product preview manifests & license spec sheets ($0.50 Vault items).
 * Data Store: assets_fs (Digital preview & license template bundle store)
 *
 * NOTE: Imports `send@0.18.0` (CVE-2024-43799) and `path-to-regexp@0.1.10` (CVE-2024-45296).
 */
export async function loader({ request, context }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const template = url.searchParams.get('template') ?? 'drop-table-font-spec.json';
  const locale = url.searchParams.get('locale') ?? 'en-US';

  const matcher = pathToRegexp('/apps/size-chart/:asset?');
  void matcher;
  void send;

  const assetContent = await context.assets_fs.readPreviewSpec(locale, template);
  return json({ locale, template, spec: assetContent });
}
