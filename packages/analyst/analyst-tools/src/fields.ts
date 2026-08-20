/**
 * tshark 4.4.16 field names this analyst stack accepts or rejects.
 * These are protocol facts, not deployment tunables.
 * @module @deepseek-ai/dsh-analyst-tools/fields
 */

/** Fields that look useful but do not exist (or do not mean what analysts expect) in tshark 4.4.16. */
export const INVALID_TSHARK_FIELDS = [
  'ldap.sAMAccountName',
  'ldap.displayName',
  'kerberos.username',
  'samr.full_name',
] as const

/** Fields the analyst tools recommend for Kerberos then SAMR display-name hunts. */
export const RECOMMENDED_TSHARK_FIELDS = [
  'kerberos.CNameString',
  'samr.samr_UserInfo21.account_name',
  'samr.samr_UserInfo21.full_name',
] as const

const INVALID = new Set(INVALID_TSHARK_FIELDS.map(field => field.toLowerCase()))

/** Comma or whitespace between tshark `-e` names in a model-supplied string. */
const FIELD_SEPARATOR = /[,\s]+/

/**
 * Normalize `pcap_filter` `fields` to `-e` names before invalid-field rejection.
 * A string is one field or a comma/space-separated list. An array is used as given.
 * @param fields - schema-accepted string, string array, or omitted.
 * @returns trimmed non-empty field names, or an empty list when omitted.
 */
export function coercePcapFilterFields(fields: string | readonly string[] | undefined): string[] {
  if (fields === undefined) return []
  if (typeof fields !== 'string') return [...fields]
  return fields.split(FIELD_SEPARATOR).map(field => field.trim()).filter(field => field !== '')
}

/**
 * Reject tshark display-filter field names that are invalid on tshark 4.4.16.
 * @param fields - model-supplied `-e` field names.
 * @returns the same list when every field is usable.
 */
export function rejectInvalidTsharkFields(fields: readonly string[]): readonly string[] {
  const invalid = fields.filter(field => INVALID.has(field.toLowerCase()))
  if (invalid.length === 0) return fields
  throw new Error(
    `invalid tshark 4.4.16 field(s): ${invalid.join(', ')}. `
    + `Use ${RECOMMENDED_TSHARK_FIELDS.join(', ')}. `
    + `Do not use ${INVALID_TSHARK_FIELDS.join(', ')}.`,
  )
}
