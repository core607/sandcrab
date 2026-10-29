"""Render all Inspect attempts; missing scores and infrastructure errors count as failures."""
from collections import defaultdict
import json
from pathlib import Path


def summarize(log) -> dict:
    rows = defaultdict(list)
    for sample in log.samples or []:
        observations = (sample.store or {}).get('native_observations', [])
        agent_calls = [o for o in observations if o.get('phase', 'agent') == 'agent']
        workspace = (sample.store or {}).get('workspace_state')
        harness_calls = ({phase: sum(o.get('phase') == phase for o in observations)
                          for phase in ('setup', 'grading', 'cleanup')} if workspace is not None else None)
        artifact = workspace.get('artifact') if workspace else None
        if artifact:
            artifact = {**artifact, 'relativePath': f'artifacts/{sample.id}/{sample.epoch}/' + artifact['name']}
        usage = list((sample.model_usage or {}).values())
        scores = list((sample.scores or {}).values())
        rows[str(sample.id)].append({
            'epoch': sample.epoch,
            'passed': not sample.error and (sample.store or {}).get('cleanup') == 'PASS' and bool(scores) and all(s.value == 'C' for s in scores),
            'cleanup': (sample.store or {}).get('cleanup', 'NOT_RUN'),
            'error': sample.error.message if sample.error else None,
            'failedChecks': [s.explanation for s in scores if s.value != 'C'],
            'limit': sample.limit.type if sample.limit else None,
            'kind': (sample.metadata or {}).get('kind', 'native'),
            'apiCalls': len(agent_calls),
            'harnessApiCalls': harness_calls,
            'refusedCalls': sum(o['status'] is not None and o['status'] >= 400 for o in agent_calls),
            'transportFailures': sum(bool(o.get('error')) and o['error'] != 'response_limit' for o in agent_calls),
            'oversizedResponses': sum(o.get('error') == 'response_limit' for o in agent_calls),
            'helpReads': sum(o['path'] == '/v1/info' or o['path'].startswith('/v1/openapi') for o in agent_calls),
            'toolCalls': sum(len(getattr(m, 'tool_calls', None) or []) for m in sample.messages),
            'failedToolCalls': sum(bool(getattr(m, 'error', None)) for m in sample.messages),
            'seconds': sample.total_time,
            'inputTokens': sum(u.input_tokens + (u.input_tokens_cache_read or 0) + (u.input_tokens_cache_write or 0) for u in usage),
            'outputTokens': sum(u.output_tokens for u in usage),
            'costUsd': sum(u.total_cost for u in usage) if usage and all(u.total_cost is not None for u in usage) else None,
            'systemFingerprint': (sample.output.metadata or {}).get('systemFingerprint'),
            'servedModel': (sample.output.metadata or {}).get('servedModel'),
            'artifact': artifact,
            'gradingChecks': len(workspace.get('grading', [])) if workspace else None,
            'sandboxPython': workspace.get('sandboxPython') if workspace else None,
        })
    return {'status': log.status, 'revision': log.eval.metadata.get('revision'),
            'model': log.eval.model, 'task': log.eval.task, 'metadata': log.eval.metadata,
            'log': Path(log.location).name, 'cases': dict(rows)}


def write(log, directory: Path, budget: dict | None = None) -> dict:
    result = summarize(log)
    result['budget'] = budget
    (directory / 'summary.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    lines = ['# Sandcrab evaluation', '', f"Evidence: **{result['metadata']['evidenceKind']}**. Revision: `{result['revision']}`.",
             f"Model: `{result['model']}`. Corpus: `{result['metadata']['corpusSha256']}`.", '',
             ('Scripted results validate the harness and native interface; they do not measure model usability.'
              if result['metadata']['evidenceKind'] == 'scripted' else
              'Model-directed results measure the selected synthetic Sandcrab tasks and consumer tools. Costs are peak-rate upper estimates, not invoices.'), '',
             f"[Inspect log](logs/{result['log']}) · [Transcript viewer](viewer/index.html)", '',
             '| Case | Passes / attempts | Tool calls | Agent / harness API calls | Refused / tool errors / transport failures | Help reads | Seconds mean / max | Tokens | Cost USD |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for case, attempts in sorted(result['cases'].items(), key=lambda item: (sum(a['passed'] for a in item[1]) / len(item[1]), item[0])):
        total = lambda field: sum(a[field] or 0 for a in attempts)
        cost = f"{total('costUsd'):.6f}" if all(a['costUsd'] is not None for a in attempts) else 'unknown'
        if result['metadata']['evidenceKind'] == 'scripted':
            cost = '0 (no model calls)'
        harness = str(sum(sum(a['harnessApiCalls'].values()) for a in attempts)) if all(a['harnessApiCalls'] is not None for a in attempts) else 'not counted'
        lines.append(f"| {case} | {total('passed')} / {len(attempts)} | {total('toolCalls')} | {total('apiCalls')} / {harness} | {total('refusedCalls')} / {total('failedToolCalls')} / {total('transportFailures')} | "
                     f"{total('helpReads')} | {total('seconds') / len(attempts):.2f} / {max(a['seconds'] or 0 for a in attempts):.2f} | "
                     f"{total('inputTokens') + total('outputTokens')} | {cost} |")
    failures = [f"- {case}, trial {a['epoch']}: " + (a['error'] or ', '.join(a['failedChecks']) or 'cleanup incomplete')
                for case, attempts in result['cases'].items() for a in attempts if not a['passed']]
    if failures:
        lines.extend(['', 'Failed attempts:', '', *failures])
    artifacts = [f"- {case}, trial {a['epoch']}: [submitted tar]({a['artifact']['relativePath']}) "
                 f"({a['artifact']['bytes']} bytes, SHA-256 `{a['artifact']['sha256']}`)"
                 for case, attempts in result['cases'].items() for a in attempts if a['artifact']]
    if artifacts:
        lines.extend(['', 'Submitted artifacts:', '', *artifacts])
    if budget:
        lines.extend(['', f"Budget: USD {budget['limitUsd']}; known upper estimate: {budget['knownUpperEstimateUsd']}; "
                      f"unresolved reservations: {budget['unresolvedReservationUsd']}; maximum accounted: {budget['maximumAccountedUsd']}.",
                      f"Batch stop reason: {budget['stopped'] or 'none'}. Provider alias: `{budget['prices']['model']}`; "
                      f"advertised release: `{budget['prices']['advertised_release']}` (not an immutable API version)."])
    lines.extend(['', 'Every attempt remains in the log, including errors and limit exits. Deliberate refusal cases count in refused calls.',
                  'Agent API calls count tool traffic only. Workspace setup, grading and cleanup calls are counted separately; legacy native-case harness traffic is not counted.',
                  'No automatic model baseline comparison is made. Download the artifact and serve its viewer directory to inspect transcripts.', ''])
    (directory / 'summary.md').write_text('\n'.join(lines), encoding='utf-8')
    return result
