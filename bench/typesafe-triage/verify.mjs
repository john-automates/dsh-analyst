// The rung between the rungs: judge a proposed bind before the slow model's
// work is accepted.
//
// The SDE cascade cookbook frames its verifier as narrow "is something wrong?"
// questions, one per failure mode, max-aggregated behind a single gate, so one
// confident red flag cannot be averaged away. The failure modes here are not
// invented: they are `bind.ts`'s own deny reasons.
//
//   LAN_C2_REASON            role c2 cannot be a LAN address
//   CDN_C2_REASON            role c2 cannot be a well-known CDN or update dest
//   VICTIM_COUNT_REASON      exactly one victim
//   (inverted close)         victim and c2 the wrong way round
//   (leftover workstation)   a bound victim that is really DC / gateway / file server
//   (AD SRV locator)         a hostname that is a service record, not a computer
//   (machine SAM)            a `...$` account persisted as the human user
//
// The exact ones stay exact. `isLanIpv4` and counting victims are arithmetic and
// belong in code -- a model should never be asked to decide whether 10.9.10.101
// is RFC1918. Only the judgments that need to know what a thing *is* go to Jev.
import { isLanIpv4 } from './baseline.mjs'

export const GATE = Number(process.env.BENCH_GATE ?? 0.7)

export const VERIFY_QUESTIONS = {
  c2_is_benign_service: {
    type: 'noul',
    instructions:
      'Something is wrong with this bind: the endpoint labelled `c2` is not ' +
      'attacker infrastructure at all. It is a content delivery network, an ' +
      'operating-system or software update service, a certificate revocation ' +
      'responder, an analytics or advertising beacon, or another ordinary ' +
      'service the host would contact whether or not it were infected. Judge ' +
      'the destination itself. A hosting provider, a reverse proxy, or a CDN ' +
      'sitting in front of an attacker-registered domain does not make the ' +
      'destination benign -- what matters is whose service is being reached.',
  },
  roles_inverted: {
    type: 'noul',
    instructions:
      'Something is wrong with this bind: the two roles are the wrong way ' +
      'round. The endpoint labelled `victim` is the attacker-controlled side, ' +
      'and the endpoint labelled `c2` is the compromised host being ' +
      'investigated.',
  },
  victim_is_infrastructure: {
    type: 'noul',
    instructions:
      'Something is wrong with this bind: the endpoint labelled `victim` is not ' +
      'a user workstation. It is server or network infrastructure -- a domain ' +
      'controller, a DNS or DHCP server, a file server, a printer, or the ' +
      'network gateway -- which is the wrong thing to name as the infected ' +
      'host in this report.',
  },
  hostname_not_a_workstation: {
    type: 'noul',
    instructions:
      'Something is wrong with this bind: the hostname recorded for the victim ' +
      'is not a computer name. It is a service locator or directory record ' +
      '(the underscored `_ldap._tcp...`, `_msdcs.`, or `_sites.dc.` forms an ' +
      'Active Directory client looks up), a DNS domain or workgroup name, or ' +
      'another label that names a service rather than a machine.',
  },
  user_is_machine_account: {
    type: 'noul',
    instructions:
      'Something is wrong with this bind: the account recorded for the victim ' +
      'is not a person. It is a computer or service account -- the kind whose ' +
      'name ends in a dollar sign, or that names a service rather than a human ' +
      'being who sits at the keyboard.',
  },
}

/**
 * Only the dimensions this proposal actually has evidence for.
 *
 * The cascade cookbook gives empty fields an absence check and nothing else,
 * and the first run showed why: asked about a victim with no recorded account,
 * `user_is_machine_account` still answered 0.39-0.44, and under max-aggregation
 * that noise became the reported worst dimension on destinations whose real
 * problem was elsewhere. A question with no evidence to judge is not asked.
 *
 * @param extra - recorded hostname / user for the victim, when harvested.
 * @returns the applicable subset of {@link VERIFY_QUESTIONS}.
 */
export function questionsFor(extra = {}) {
  const out = {
    c2_is_benign_service: VERIFY_QUESTIONS.c2_is_benign_service,
    roles_inverted: VERIFY_QUESTIONS.roles_inverted,
    victim_is_infrastructure: VERIFY_QUESTIONS.victim_is_infrastructure,
  }
  if (extra.hostname !== undefined) {
    out.hostname_not_a_workstation = VERIFY_QUESTIONS.hostname_not_a_workstation
  }
  if (extra.user !== undefined) {
    out.user_is_machine_account = VERIFY_QUESTIONS.user_is_machine_account
  }
  return out
}

/**
 * Exact checks, kept out of the model. These are arithmetic on an address, not
 * judgments about what a destination is.
 *
 * @param bind - `{ victim, c2 }` endpoints.
 * @returns the deny reason `bind.ts` would give, or undefined.
 */
export function exactDenial(bind) {
  if (isLanIpv4(bind.c2.ip)) return 'role c2 cannot be a LAN address'
  if (!isLanIpv4(bind.victim.ip)) return 'victim is not a LAN address'
  return undefined
}

/**
 * The state the verifier judges: the proposal plus what the capture actually
 * showed for each endpoint. No file names, nothing from the notes.
 *
 * @param bind - `{ victim, c2 }` observations.
 * @param extra - optional recorded hostname / user for the victim.
 * @returns the state object.
 */
export function verifyState(bind, extra = {}) {
  return {
    proposed_bind: {
      victim: 'the compromised host being investigated',
      c2: 'the attacker infrastructure it was talking to',
    },
    endpoint_labelled_victim: {
      address: bind.victim.ip,
      on_the_local_network: isLanIpv4(bind.victim.ip),
      ...(extra.hostname !== undefined ? { recorded_hostname: extra.hostname } : {}),
      ...(extra.user !== undefined ? { recorded_account: extra.user } : {}),
      ...bind.victim.state,
    },
    endpoint_labelled_c2: {
      address: bind.c2.ip,
      on_the_local_network: isLanIpv4(bind.c2.ip),
      ...bind.c2.state,
    },
  }
}

/**
 * Max-aggregation, as the cascade cookbook specifies: one confident red flag
 * escalates, rather than being averaged away by four calm ones.
 *
 * @param answers - the verifier's Noul answers.
 * @returns `{ flag, worst, scores }`.
 */
export function gate(answers) {
  const scores = Object.fromEntries(
    Object.keys(VERIFY_QUESTIONS)
      .filter((k) => answers[k] !== undefined)
      .map((k) => [k, answers[k].noul]),
  )
  const entries = Object.entries(scores)
  if (entries.length === 0) return { flag: false, worst: undefined, score: 0, scores }
  const [worst, score] = entries.reduce((a, b) => (b[1] > a[1] ? b : a))
  return { flag: score >= GATE, worst, score, scores }
}
