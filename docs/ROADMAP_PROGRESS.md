# NullPointVector Roadmap And Progress

## Purpose
This document tracks what is done, what is next, and what gates must pass before production push.

## Current Snapshot
Last updated: 2026-05-24

### Completed Foundation
- Multi-channel architecture is in place for email, sms, and voice paths.
- Vector database pipeline is active with pgvector and semantic search.
- Core ingestion and auto-triage loops are running.
- Security hardening is in place with validation, sanitization, and CI security workflows.
- Dash and API surfaces are operational.

### In Progress
- Model quality uplift for phishing detection.
- Unified metrics and evaluation pipeline across phishing, smishing, and vishing.

### Not Started
- iOS production mobile integration path (CallKit app-side integration and release workflow).

---

## Phase Plan

## Phase 1: Metrics First (No New Model Work Until This Exists)
Status: In Progress
Target: 1 week

### Deliverables
- Define one offline evaluation dataset split strategy:
  - Time-based split for realistic drift evaluation.
  - Holdout set for final reporting.
- Track core metrics per channel:
  - Precision, recall, F1, ROC-AUC, PR-AUC, false positive rate.
  - Confusion matrix by channel and risk tier.
- Add threshold report:
  - Metrics at thresholds 0.50, 0.70, 0.85, 0.90.
- Add model comparison table:
  - Baseline logistic model vs candidate models.

### Exit Criteria
- Baseline report generated from one reproducible command.
- Stored artifact with date, dataset version, and model version.

---

## Phase 2: Supervised Model Uplift
Status: Planned
Target: 2 to 3 weeks

### Deliverables
- Improve feature pipeline:
  - URL/domain lexical features.
  - Sender-domain mismatch and header anomalies.
  - Content urgency and credential-request signals.
- Train stronger supervised candidates:
  - Calibrated linear model.
  - Tree-based gradient boosting baseline.
  - Optional transformer fine-tune candidate if enough labeled data.
- Add class imbalance handling:
  - Class weights and threshold optimization by business cost.

### Exit Criteria
- At least one candidate beats baseline on PR-AUC and recall at acceptable precision.
- False positives do not regress beyond agreed limit.

---

## Phase 3: Unsupervised And Drift Safety Net
Status: Planned
Target: 1 to 2 weeks

### Deliverables
- Add unsupervised detectors for novel attacks:
  - Isolation Forest or One-Class model on embedding and engineered feature space.
  - Cluster-based outlier scoring for campaign detection.
- Drift monitoring:
  - Feature distribution drift checks.
  - Confidence shift monitoring and alerting.

### Exit Criteria
- Drift alerts trigger on synthetic and replay tests.
- Unsupervised score contributes to triage without flooding false alarms.

---

## Phase 4: Online Learning And Feedback Loop
Status: Planned
Target: 1 week

### Deliverables
- Human feedback capture for false positive and false negative corrections.
- Weekly retrain or rolling update schedule with rollback safety.
- Model registry record:
  - model_version
  - data_version
  - metrics_summary
  - deployment_timestamp

### Exit Criteria
- Safe promotion and rollback path proven in staging.

---

## Phase 5: iOS And CallKit Delivery Path
Status: Planned
Target: 2 to 4 weeks

### Clarification
- You do not purchase CallKit itself.
- You need Xcode and an Apple Developer account for signing, capabilities, and distribution.

### Deliverables
- Xcode project setup for iOS client.
- Apple Developer account and certificates/provisioning setup.
- CallKit integration path for call identification and call handling UX.
- Push path and backend event mapping if real-time signaling is required.
- App privacy, permissions, and App Store review readiness checklist.

### Exit Criteria
- TestFlight build distributed.
- End-to-end test from backend signal to client behavior passes.

---

## Release Gate Before Push And Commit
- Main branch up to date and green checks pass.
- Metrics report attached for current model release candidate.
- Security scans pass at agreed severity threshold.
- Rollback instructions validated.
- Demo script and runbook updated.

---

## Progress Tracker

### Program Percent Complete (estimate)
- Platform foundation: 75%
- ML quality program: 25%
- Mobile integration: 5%
- Production readiness end-to-end: 45%

### Weekly Status Template
- Week of: YYYY-MM-DD
- Wins:
- Risks:
- Blockers:
- Metric delta:
- Next week goals:

---

## Immediate Next 7 Days
- Build baseline metrics command and output artifact format.
- Freeze current logistic baseline numbers on holdout.
- Create candidate model matrix and rank by PR-AUC and false positive rate.
- Define mobile technical spike scope for Xcode and Apple account setup.
