export const meta = {
  name: 'qa-assessment',
  description: 'Full QA assessment with batch reviewers and synthesis',
  phases: [
    { title: 'Review', detail: 'Batch reviewers assess scenarios against checklist' },
    { title: 'Synthesize', detail: 'Merge findings into QA report' },
  ],
}

const REVIEW_SCHEMA = {
  type: 'object',
  properties: {
    batch: { type: 'string' },
    scenario_count: { type: 'integer' },
    scenarios: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          verdict: { type: 'string', enum: ['clean', 'minor', 'moderate', 'critical'] },
          findings: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                check: { type: 'string' },
                severity: { type: 'string', enum: ['minor', 'moderate', 'critical'] },
                description: { type: 'string' }
              },
              required: ['check', 'severity', 'description']
            }
          }
        },
        required: ['id', 'verdict', 'findings']
      }
    }
  },
  required: ['batch', 'scenario_count', 'scenarios']
}

const config = typeof args === 'string' ? JSON.parse(args) : args
const BASE = '/Users/hjrnunes/workspace/hjrnunes/scenario-forge'
const CHECKLIST = BASE + '/ai/extended-context/quality-assessment-checklist.md'

phase('Review')
const reviews = await parallel(config.batches.map(batch => () => {
  const scenarioList = batch.scenarios.map(s => '- ' + s + '.yaml / ' + s + '.feature').join('\n')
  return agent('You are a QA reviewer for scenario-forge pipeline output. Review EVERY scenario in your batch against the quality assessment checklist. Do NOT sample or skip any scenario — review all ' + batch.scenarios.length + ' scenarios.\n\n' +
    '## Instructions\n' +
    '1. Read the quality checklist at: ' + CHECKLIST + '\n' +
    '2. Read the capability profile at: ' + BASE + '/' + config.capProfilePath + '\n' +
    '3. For each scenario below, read both the .yaml and .feature file from: ' + BASE + '/' + config.scenariosDir + '/\n' +
    '4. Apply checklist sections 2a through 2h to each scenario\n' +
    '5. Record findings with severity and the specific checklist sub-item violated\n' +
    '6. Assign overall verdict per scenario\n\n' +
    '## Your Batch: ' + batch.name + ' (' + batch.threats + ')\n\n' +
    'Scenarios to review:\n' + scenarioList + '\n\n' +
    '## Known Accepted Behaviors (NOT defects — do NOT flag these)\n' +
    '- T6 cross-reference on tree nodes — per-node threat_id reflects mechanism, not scenario-level threat (decision-t6-crossref-policy)\n' +
    '- Partial technique provenance — using 1 of 2 seed techniques is acceptable (decision-technique-provenance-partial)\n' +
    '- Entry point directionality — RAG knowledge-grounding = input direction (decision-entry-point-directionality)\n' +
    '- Minor zone tag disagreements between narrative (Call 1) and tree/Gherkin (Call 2) when tree and Gherkin are internally consistent (decision-zone-sequence-narrative-tree-mismatch)\n\n' +
    '## Severity Guide\n' +
    '- critical: Phantom capability (tools/memory/capabilities the system does not have), wrong threat category, broken causal chain, technique not in seed allowed set\n' +
    '- moderate: Actor-type mismatch with behavior, zone boundary violation, significant narrative-Gherkin divergence, parsimony violation (leaf count > 2 * technique_count + 2)\n' +
    '- minor: Slight zone tag disagreement, minor wording inconsistency, technique semantic fit could improve, near-duplicate title\n\n' +
    'Review ALL ' + batch.scenarios.length + ' scenarios. Return structured results.', {
    label: 'review:' + batch.name,
    phase: 'Review',
    schema: REVIEW_SCHEMA,
  })
}))

const validReviews = reviews.filter(Boolean)
log(validReviews.length + '/' + config.batches.length + ' batches reviewed')

phase('Synthesize')
const reviewJson = JSON.stringify(validReviews, null, 2)

const result = await agent('You are a QA synthesis agent. Merge batch reviewer findings into a comprehensive QA report.\n\n' +
  '## Task\n' +
  'Write a QA report to: ' + BASE + '/' + config.reportPath + '\n' +
  'Follow the EXACT format of previous QA reports. Read the format reference at: ' + BASE + '/' + config.prevReportPath + '\n\n' +
  '## Run: ' + config.run + '\n' +
  'Scenario count: ' + config.scenarioCount + ' (previous ' + config.prevRunName + ': ' + config.prevScenarioCount + ')\n\n' +
  '## Current Eval Metrics\n' + JSON.stringify(config.currentMetrics, null, 2) + '\n\n' +
  '## Previous Run (' + config.prevRunName + ') Metrics\n' + JSON.stringify(config.prevMetrics, null, 2) + '\n\n' +
  '## Batch Reviewer Results\n' + reviewJson + '\n\n' +
  '## Report Structure (follow exactly)\n' +
  '1. Header: assessment scope, method, scenario count change from previous version\n' +
  '2. Known accepted behaviors section\n' +
  '3. Section 1 — Automated Metrics: table with current vs previous and deltas\n' +
  '4. Section 2 — Per-Scenario Review Summary: table (batch | threats | scenarios | critical | moderate | minor | clean | clean%)\n' +
  '5. Clean scenarios list with shared traits\n' +
  '6. Section 3 — Systemic Defects: group findings by pattern, cross-reference scenario IDs\n' +
  '7. Section 4 — Defect summary table (defect type | count | severity | trend)\n' +
  '8. Section 5 — Version-over-version comparison with key observations\n' +
  '9. Section 6 — Recommendations for next iteration (prioritized)\n\n' +
  '## Critical Rules\n' +
  '- List every clean scenario ID\n' +
  '- Every finding must reference specific scenario IDs\n' +
  '- Include clean % per batch AND overall\n' +
  '- Scenario severity = its worst finding\n' +
  '- Do NOT invent findings beyond what reviewers reported\n' +
  '- Do NOT re-assess scenarios — trust reviewer verdicts\n\n' +
  'Write the complete report file, then return a one-line summary: "Report written to ' + config.reportPath + '. X/Y clean (Z%)"', { label: 'synthesize' })

return result
