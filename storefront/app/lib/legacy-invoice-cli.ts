import { parseStringPromise } from 'xml2js';

/**
 * Offline archive script (NOT imported by any exposed HTTP route under app/routes/!).
 * Proves CSR Asset-Graph multi-hop reachability rejects package-only CPE matches (`xml2js@0.4.22`).
 */
export async function parseLegacyBatchXml(rawXml: string) {
  return parseStringPromise(rawXml);
}
