"""
Held-out golden evaluation for the phishing detector.

WHY THIS EXISTS:
"100% on 16 hand-picked cases" is not a real accuracy number — the resume
claims (94% detection, 80% FP reduction) are only credible if they are measured
on a fixed, versioned set the model was NEVER trained on. This module is that
measurement, and it doubles as the CI regression gate: a model can only ship if
it still clears the thresholds here.

The golden set (golden_eval.jsonl) deliberately includes adversarial slices:
  - pump_fake : "was this you?" phishing that fails sender auth or carries a
                bad URL  (must be caught despite the safe-phrase)
  - auth_pass : legitimate alerts that pass aligned SPF/DKIM/DMARC
                (must NOT be flagged — this is the false-positive landmine)
  - leet / spear / url : obfuscation, no-keyword spear-phish, malicious links

Run directly:   python -m eval.evaluate         (from phish_mlm/)
                python PhishGuard/phish_mlm/eval/evaluate.py
"""
import json
from pathlib import Path

GOLDEN_PATH = Path(__file__).parent / 'golden_eval.jsonl'

# CI / promotion gate. A candidate model must clear ALL of these.
GATE = {
    'min_accuracy': 0.90,
    'max_fpr': 0.10,            # false positives are expensive for a mail filter
    'min_pump_fake_recall': 1.0,  # the pump-fake must NEVER get through
}


def load_golden(path: Path = GOLDEN_PATH) -> list:
    rows = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _get_detector(detector=None):
    if detector is not None:
        return detector
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
    from PhishGuard.phish_mlm.phishing_detector import detector as singleton
    return singleton


def evaluate(detector=None, rows=None) -> dict:
    """Run the detector over the golden set and return a metrics dict."""
    detector = _get_detector(detector)
    rows = rows if rows is not None else load_golden()

    tp = tn = fp = fn = 0
    per_tag = {}          # tag -> [correct, total]
    failures = []         # misclassified rows for debugging

    for row in rows:
        expected = int(row['label'])
        pred, conf = detector.predict(row)
        correct = int(pred == expected)

        if expected == 1 and pred == 1:
            tp += 1
        elif expected == 0 and pred == 0:
            tn += 1
        elif expected == 0 and pred == 1:
            fp += 1
        else:
            fn += 1

        for tag in row.get('tags', []) or ['untagged']:
            slot = per_tag.setdefault(tag, [0, 0])
            slot[0] += correct
            slot[1] += 1

        if not correct:
            failures.append({
                'expected': expected, 'pred': pred, 'conf': round(conf, 3),
                'tags': row.get('tags', []),
                'text': (row.get('subject', '') + ' | ' + row.get('body', ''))[:90],
            })

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0          # detection rate
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    pump = per_tag.get('pump_fake', [0, 0])
    pump_recall = pump[0] / pump[1] if pump[1] else 1.0

    return {
        'n': total,
        'accuracy': accuracy, 'precision': precision, 'recall': recall,
        'specificity': specificity, 'fpr': fpr, 'f1': f1,
        'confusion': {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn},
        'pump_fake_recall': pump_recall,
        'per_tag': {k: round(v[0] / v[1], 3) for k, v in sorted(per_tag.items())},
        'failures': failures,
    }


def passes_gate(metrics: dict, gate: dict = GATE) -> bool:
    return (
        metrics['accuracy'] >= gate['min_accuracy']
        and metrics['fpr'] <= gate['max_fpr']
        and metrics['pump_fake_recall'] >= gate['min_pump_fake_recall']
    )


def run_golden_eval(detector=None) -> dict:
    """Pretty-print the golden evaluation and return the metrics dict."""
    m = evaluate(detector)
    c = m['confusion']
    print("\n=== Golden held-out evaluation ===")
    print(f"  samples           : {m['n']}")
    print(f"  accuracy          : {m['accuracy']:.1%}")
    print(f"  detection (recall): {m['recall']:.1%}")
    print(f"  precision         : {m['precision']:.1%}")
    print(f"  false-positive rate: {m['fpr']:.1%}")
    print(f"  F1                : {m['f1']:.3f}")
    print(f"  confusion         : TP={c['tp']} TN={c['tn']} FP={c['fp']} FN={c['fn']}")
    print(f"  pump-fake recall  : {m['pump_fake_recall']:.0%}  (must be 100%)")
    print("  per-tag accuracy  :")
    for tag, acc in m['per_tag'].items():
        print(f"      {tag:<14} {acc:.0%}")
    if m['failures']:
        print(f"  misclassified ({len(m['failures'])}):")
        for f in m['failures']:
            arrow = f"{f['expected']}→{f['pred']}"
            print(f"      [{arrow} {f['conf']:.0%}] {f['tags']} {f['text']}")
    gate_ok = passes_gate(m)
    print(f"\n  GATE: {'PASS ✅' if gate_ok else 'FAIL ❌'} "
          f"(acc≥{GATE['min_accuracy']:.0%}, fpr≤{GATE['max_fpr']:.0%}, "
          f"pump-fake recall=100%)")
    return m


if __name__ == '__main__':
    import sys
    metrics = run_golden_eval()
    sys.exit(0 if passes_gate(metrics) else 1)
