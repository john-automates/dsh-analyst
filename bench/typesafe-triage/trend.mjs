// Render the scorecard ledger: one row per investigation, newest last.
//
//   node bench/typesafe-triage/trend.mjs [--case=YYYY-MM-DD]
//
// `variance` at the bottom answers the question a buyer asks second: run the
// same capture twice, do I get the same answer? Runs are grouped by case and
// config, because a difference across configs is a change, not variance.
import fs from 'node:fs/promises'
import path from 'node:path'

const ledger = path.join(import.meta.dirname, 'runs/scorecard.jsonl')
const rows = (await fs.readFile(ledger, 'utf8')).split('\n')
  .filter((l) => l !== '').map((l) => JSON.parse(l))
const only = process.argv.find((a) => a.startsWith('--case='))?.slice(7)
const shown = only === undefined ? rows : rows.filter((r) => r.case === only)

const cell = (v, w) => String(v ?? '-').padEnd(w)
const head = `${cell('run', 20)}${cell('C2', 4)}${cell('IOC%', 6)}${cell('grnd%', 7)}`
  + `${cell('cite%', 7)}${cell('lost', 16)}${cell('$', 9)}${cell('bind_s', 8)}`
  + `${cell('wall_s', 8)}${cell('refu', 6)}${cell('rule', 6)}`
console.log(`\n${head}\n${'-'.repeat(head.length)}`)
for (const r of shown) {
  const p = r.production
  const b = r.bench ?? {}
  const rule = r.config.ruleContradiction ? 'MIXED' : r.config.ruleSoftened ? 'soft' : 'hard'
  console.log(
    cell(r.run, 20) + cell(b.c2Correct === true ? 'Y' : 'n', 4)
    + cell(b.iocCoveragePct, 6) + cell(p.groundedPct, 7) + cell(p.citedEndpointsPct, 7)
    + cell(p.harnessLostFields.join(',') || '-', 16) + cell(p.costUsd, 9)
    + cell(p.timeToFirstBindSec, 8) + cell(p.wallSec, 8) + cell(p.refusals, 6) + cell(rule, 6),
  )
}

// Variance: same case AND same rule config, repeated.
const groups = new Map()
for (const r of shown) {
  const rule = r.config.ruleContradiction ? 'mixed' : r.config.ruleSoftened ? 'soft' : 'hard'
  // Capture naming is an input difference, so it cannot share a variance group.
  const key = `${r.case}|${rule}|${r.config.captureNamesNeutral === false ? 'named' : 'neutral'}`
  groups.set(key, [...groups.get(key) ?? [], r])
}
const repeated = [...groups.entries()].filter(([, g]) => g.length > 1)
if (repeated.length === 0) {
  console.log('\nvariance: no case has been run twice on one config yet.')
} else {
  console.log('\nvariance (same case, same config):')
  for (const [key, g] of repeated) {
    const spread = (pick) => {
      const vals = g.map(pick).filter((v) => v !== undefined)
      return vals.length === 0 ? '-' : `${Math.min(...vals)}-${Math.max(...vals)}`
    }
    const c2 = new Set(g.map((r) => r.bench?.boundC2))
    console.log(`  ${key}  n=${g.length}`)
    console.log(`    bound C2     ${c2.size === 1 ? `stable (${[...c2][0]})` : `UNSTABLE ${[...c2].join(' vs ')}`}`)
    console.log(`    IOC coverage ${spread((r) => r.bench?.iocCoveragePct)}%`)
    console.log(`    grounded     ${spread((r) => r.production.groundedPct)}%`)
    console.log(`    cost         $${spread((r) => r.production.costUsd)}`)
    console.log(`    wall         ${spread((r) => r.production.wallSec)}s`)
  }
}
console.log()
