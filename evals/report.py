"""Render all Inspect attempts; missing scores and infrastructure errors count as failures."""
from collections import defaultdict
import json
from pathlib import Path


def summarize(log) -> dict:
    rows = defaultdict(list)
    for sample in log.samples or []:
        observations = (sample.store or {}).get('native_observations', [])
        usage = list((sample.model_usage or {}).values())
        scores = list((sample.scores or {}).values())
        rows[str(sample.id)].append({
            'epoch': sample.epoch,
            'passed': not sample.error and (sample.store or {}).get('cleanup') == 'PASS' and bool(scores) and all(s.value == 'C' for s in scores),
            'cleanup': (sample.store or {}).get('cleanup', 'NOT_RUN'),
            'error': sample.error.message if sample.error else None,
            'failedChecks': [s.explanation for s in scores if s.value != 'C'],
            'limit': sample.limit.type if sample.limit else None,
            'apiCalls': len(observations),
            'refusedCalls': sum(o['status'] >= 400 for o in observations),
            'helpReads': sum(o['path'] in {'/v1/info', '/v1/openapi'} for o in observations),
            'toolCalls': sum(len(getattr(m, 'tool_calls', None) or []) for m in sample.messages),
            'failedToolCalls': sum(bool(getattr(m, 'error', None)) for m in sample.messages),
            'seconds': sample.total_time,
            'inputTokens': sum(u.input_tokens + (u.input_tokens_cache_read or 0) + (u.input_tokens_cache_write or 0) for u in usage),
            'outputTokens': sum(u.output_tokens for u in usage),
            'costUsd': sum(u.total_cost for u in usage) if usage and all(u.total_cost is not None for u in usage) else None,
            'systemFingerprint': (sample.output.metadata or {}).get('systemFingerprint'),
            'servedModel': (sample.output.metadata or {}).get('servedModel'),
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
              'Model-directed results measure these synthetic native API tasks. Costs are peak-rate upper estimates, not invoices.'), '',
             f"[Inspect log](logs/{result['log']}) · [Transcript viewer](viewer/index.html)", '',
             '| Case | Passes / attempts | Tool calls | API calls | Refused / failed calls | Help reads | Seconds mean / max | Tokens | Cost USD |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for case, attempts in sorted(result['cases'].items(), key=lambda item: (sum(a['passed'] for a in item[1]) / len(item[1]), item[0])):
        total = lambda field: sum(a[field] or 0 for a in attempts)
        cost = f"{total('costUsd'):.6f}" if all(a['costUsd'] is not None for a in attempts) else 'unknown'
        if result['metadata']['evidenceKind'] == 'scripted':
            cost = '0 (no model calls)'
        lines.append(f"| {case} | {total('passed')} / {len(attempts)} | {total('toolCalls')} | {total('apiCalls')} | {total('refusedCalls')} / {total('failedToolCalls')} | "
                     f"{total('helpReads')} | {total('seconds') / len(attempts):.2f} / {max(a['seconds'] or 0 for a in attempts):.2f} | "
                     f"{total('inputTokens') + total('outputTokens')} | {cost} |")
    failures = [f"- {case}, trial {a['epoch']}: " + (a['error'] or ', '.join(a['failedChecks']) or 'cleanup incomplete')
                for case, attempts in result['cases'].items() for a in attempts if not a['passed']]
    if failures:
        lines.extend(['', 'Failed attempts:', '', *failures])
    if budget:
        lines.extend(['', f"Budget: USD {budget['limitUsd']}; known upper estimate: {budget['knownUpperEstimateUsd']}; "
                      f"unresolved reservations: {budget['unresolvedReservationUsd']}; maximum accounted: {budget['maximumAccountedUsd']}.",
                      f"Batch stop reason: {budget['stopped'] or 'none'}. Provider alias: `{budget['prices']['model']}`; "
                      f"advertised release: `{budget['prices']['advertised_release']}` (not an immutable API version)."])
    lines.extend(['', 'Every attempt remains in the log, including errors and limit exits. Deliberate refusal cases count in refused calls.',
                  'No automatic model baseline comparison is made. Download the artifact and serve its viewer directory to inspect transcripts.', ''])
    (directory / 'summary.md').write_text('\n'.join(lines), encoding='utf-8')
    return result
