# 06 — State (UML state machines)

How each long-lived object moves through its states, and — just as important —
which transitions are terminal, which are recoverable, and which states
*cannot* be escaped by anything the UI offers.

Related: [interaction.md](interaction.md) · [activity.md](activity.md) ·
[data-model.md](data-model.md)

## Investigation

```mermaid
stateDiagram-v2
    [*] --> draft
    draft --> running : POST /investigations/{id}/run
    running --> draft : run failed before any artifact
    running --> ready : run.status = done
    ready --> running : re-run · schedule tick · gap research · manager launch
    ready --> ready : schedule fires again
    draft --> [*] : delete
    running --> draft : delete (cascades)
    ready --> [*] : delete (cascades)

    note right of running<br/>A run that is already going is not<br/>restarted: a second POST returns 429.<br/>The scheduler and the gap loop both<br/>check before launching.
    end note

    note right of ready<br/>A recurring investigation keeps its<br/>own status "ready" between ticks.<br/>The schedule (cron + next_run_at +<br/>max_items + max_rounds) is what makes<br/>"ready" a repeating state.
    end note

```

## Collection run (`agent_runs.status`)

```mermaid
stateDiagram-v2
    [*] --> running
    running --> done : run.end + summary event
    running --> error : unhandled exception, error text stored
    error --> running : re-run (a new run row, the old one is kept)

    note right of running<br/>A row is created before the worker<br/>thread starts, so a run that dies with<br/>the process still appears in history<br/>rather than vanishing.
    end note
    note right of error<br/>The error is stored on the row and<br/>surfaced in the run list. Partial<br/>artifacts collected before the failure<br/>are kept — a half-finished sweep is<br/>still evidence.
    end note

```

## Security run — the one with a human in the loop

```mermaid
stateDiagram-v2
    [*] --> running : launch (run row + job enqueued)
    running --> awaiting_approval : require_approval, no approved plan (control-analyst holds)
    running --> done : assessment persisted, run.end
    running --> error : agent or job failure
    awaiting_approval --> running : approve → new job enqueued under the same key
    awaiting_approval --> error : deny
    error --> running : resume_security_assessment (re-queues)
    done --> [*]
    error --> [*]

    note right of awaiting_approval<br/>The job that parked the run COMPLETED<br/>normally (status done). done is not in<br/>the live set (pending/retry/running), so<br/>the approval's fresh job can reuse key<br/>security:{run_id} without colliding.<br/>"parked" is a state of the run, not of<br/>the job.
    end note
    note right of running<br/>"busy" for this investigation is<br/>running or awaiting_approval — a run<br/>parked at a gate still holds the<br/>investigation.
    end note

```

## Job

```mermaid
stateDiagram-v2
    [*] --> pending : enqueue (row written first)
    pending --> running : claim() by a worker
    retry --> running : claim() after next_attempt_at
    running --> done : complete()
    running --> retry : fail(retry=true), attempts < max
    retry --> failed : fail(), attempts == max_attempts
    running --> failed : fail(retry=false)
    running --> pending : lease expired → recover_orphans()
    done --> [*]
    failed --> [*]

    note right of pending<br/>The row exists before any thread, so a<br/>crash between enqueue and start leaves<br/>visible, countable work.
    end note
    note right of retry<br/>Backoff is on next_attempt_at, and the<br/>live-key index is partial (only<br/>pending/retry/running), so a re-enqueue<br/>of the same key re-attaches instead of<br/>duplicating.
    end note
    note right of running<br/>A worker heartbeats its lease. Only an<br/>expired lease is recoverable, so a<br/>slow job is never duplicated by a<br/>second worker.
    end note

```

## Explanation

```mermaid
stateDiagram-v2
    [*] --> running
    running --> done : answer + trace + quiz stored
    running --> error : unhandled failure
    done --> running : investigate_gaps → a new run row (the old answer is kept)
    done --> done : watched → a re-answer (drift verdict attached)
    done --> done : bookmarked
    error --> [*]
    done --> [*]

    note right of running<br/>meta.phase is the finer-grained view the<br/>UI polls: researching → composing →<br/>checking → revising → enriching. The<br/>run is "running" through all of it.
    end note
    note right of done<br/>Done is not final: a watched<br/>explanation is re-answered by the<br/>scheduler, and the old answer is kept<br/>alongside the new one — the drift<br/>verdict is the record of what changed.
    end note

```

## Manager run

```mermaid
stateDiagram-v2
    [*] --> running : POST /api/manager/run
    running --> compiled : compile_run (all children terminal, synthesis stored)
    running --> running : statuses derived from child runs (no state of its own)
    compiled --> compiled : compile_run again → idempotent
    compiled --> [*]

    note right of running<br/>ManagerRun carries no per-child<br/>progress of its own: "all_done" is<br/>computed live from the agent/security<br/>tables. A restart mid-fan-out therefore<br/>strands nothing — the children are<br/>ordinary runs.
    end note
    note right of compiled<br/>Compiling is refused with 409 while any<br/>child is still running: there is<br/>nothing to synthesise yet.
    end note

```

## Artifact — review and drift are orthogonal to collection

```mermaid
stateDiagram-v2
    [*] --> pending : written by the agent
    [*] --> pending : written by hand
    pending --> accepted : accept
    pending --> rejected : reject (reversible)
    rejected --> pending : reset (reverse the decision)
    accepted --> [*]
    pending --> [*]
    rejected --> [*]

    state drift {
        [*] --> clean
        clean --> drifted : detect-drift flags it (kept, dimmed)
        drifted --> clean : a later sweep finds it on-brief
    }

    note right of drift<br/>Drift is a flag, not a state. Nothing<br/>is deleted for being off-brief: the<br/>artifact stays, dimmed in the graph,<br/>with a "drift" pill in the review<br/>queue. Hiding a person from seeing<br/>what was collected is a different<br/>decision, and it is explicit<br/>(investigation.hidden).
    end note

```

## Ledger run (a task, or a session)

```mermaid
stateDiagram-v2
    [*] --> open : create_run (mandate hashed at creation)
    open --> closed : run.end (status=closed)
    open --> aborted : context manager exits on error, or close_run(status=aborted)
    open --> open : events appended, head_hash advances
    closed --> [*]
    aborted --> [*]

    note right of open<br/>Two kinds share this machine.<br/>A task's chain holds its own events.<br/>A session's chain holds one anchor per<br/>adopted task, in adoption order —<br/>so each task verifies alone and the<br/>session independently proves the order<br/>they happened in.
    end note
    note right of closed<br/>Closing is not deletion: the chain,<br/>its claims and its approvals stay<br/>queryable and verifiable after the<br/>investigation that produced them is<br/>gone. That is the point of the ledger.
    end note

```

## Approval

```mermaid
stateDiagram-v2
    [*] --> pending : approval.request (hold verdict on the chain)
    pending --> granted : decided_by ≠ requested_by
    pending --> denied : decided_by ≠ requested_by
    pending --> pending : nothing yet — the run stays parked
    granted --> [*]
    denied --> [*]

    note right of pending<br/>The decision is itself a chained<br/>event, so it cannot be forged into<br/>the record after the fact. An<br/>identical requester/approver is 403,
        and an empty identity fails closed.
    end note

```

## Security assessment — an append-only record

```mermaid
stateDiagram-v2
    [*] --> empty : shell row created with the run
    empty --> scored : report built, aggregates + pack fingerprint stored
    scored --> scored : a later sweep refreshes the risk view
    scored --> [*]

    note right of scored<br/>Assessments are never mutated by a<br/>human. Re-running an assessment writes<br/>a new run (and can write a new row);<br/>the previous report is what it said at<br/>the time, including the threat-pack<br/>version and fingerprint it was scored<br/>against.
    end note

```

## The scheduler, as a state machine

```mermaid
stateDiagram-v2
    [*] --> ticking : boot, every 10 min
    ticking --> ticking : due investigations launched (not busy, not hidden)
    ticking --> ticking : watched explanations re-answered (drift verdict)
    ticking --> ticking : missed windows skipped, never backfilled
    ticking --> [*] : shutdown

    note right of ticking<br/>The scheduler is the only component<br/>that acts without a person, so every<br/>state transition here is also an<br/>event on the ledger (actor_type<br/>"system") — the app can be read back<br/>to see what it did while nobody was<br/>looking.
    end note

```

## Related

- Call order: [interaction.md](interaction.md)
- Decisions inside each flow: [activity.md](activity.md)
- Which transitions a person can trigger from the UI: [ui-interaction.md](ui-interaction.md)
