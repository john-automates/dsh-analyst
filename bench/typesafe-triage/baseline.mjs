// The pilot to beat: the heuristic the analyst plugin ships today.
//
// Imported from the built package, never reimplemented. `bind.ts` refuses a C2
// that is a "well-known CDN or update destination", and `index.ts` omits such
// dests from `c2_ips`, using exactly these three predicates: a 19-entry
// registrable-suffix list plus the published Cloudflare and Fastly anycast
// prefixes. That is the whole of the plugin's semantic understanding of a
// destination, and this bench grades it against the same observation the model
// sees.
//
// Relative path to the built entry, not the package name: tsdown bundles the
// package into `lib/index.js`, so `harvest.js` has no separate file on disk,
// and `lib/*` is not an exported subpath anyway.
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const ENTRY = path.resolve(
  import.meta.dirname, '../../packages/analyst/investigation/lib/index.js')

let plugin
try {
  plugin = await import(pathToFileURL(ENTRY).href)
} catch (error) {
  throw new Error(
    `bench baseline needs the built analyst package (${ENTRY}). ` +
    `Run \`pnpm run build\` first.\n${error.message}`,
  )
}

export const { isCdnOrUpdateName, isCloudflareIpv4, isFastlyIpv4, isLanIpv4 } = plugin

/**
 * The shipped rule, stated as the same judgment the model is asked: a non-LAN
 * destination counts as infection traffic unless one of the three predicates
 * fires. The plugin has no other way to tell a payload host from a benign one.
 *
 * @param dest - `{ ip, names }` from the observation.
 * @returns 1 when the plugin would treat it as a candidate C2, else 0.
 */
export function baselineCall(dest) {
  if (isLanIpv4(dest.ip)) return 0
  if (isCloudflareIpv4(dest.ip) || isFastlyIpv4(dest.ip)) return 0
  if (dest.names.some((n) => isCdnOrUpdateName(n))) return 0
  return 1
}
