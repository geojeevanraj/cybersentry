# ADR-0002: Correlation is deterministic, not learned
 
**Status:** Accepted
**Date:** 2026-09-11
 
## Context
 
An analyst must be able to explain why twelve alerts became one incident. A learned
grouping that cannot be justified turns into a trust problem during an actual
intrusion, which is the worst possible moment.
 
## Decision
 
`libs/sentry_domain/correlation.py` groups detections by shared entity (host,
user, source IP, process lineage) within a configurable time window, using a
stable dedup key. Models may raise or lower a detection's score but never decide
grouping.
 
## Consequences
 
+ Every incident's membership is explainable and reproducible.
+ Replaying a day of detections rebuilds the same incidents.- Sophisticated low-and-slow campaigns spanning the window need explicit
  hunting rather than automatic grouping.