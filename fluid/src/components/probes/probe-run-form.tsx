'use client';

import * as React from 'react';
import { Lock, Send } from 'lucide-react';
import { postParsed } from '@/lib/api/client';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import type { ProbeResult } from './probe-types';

const zProbeRun = z
  .object({
    probe_id: z.string(),
    attack_class: z.string().nullable().optional(),
    status: z.string(),
    trials_requested: z.number(),
    reason: z.string().nullable().optional(),
  })
  .passthrough();

export interface ProbeRunFormProps {
  assessmentId: number;
  library: { id: string; attack_class: string; description: string }[];
  maxTrials: number;
  onResult: (r: ProbeResult) => void;
}

/**
 * The confirm gate, made explicit.
 *
 * A probe sends an adversarial payload to a real endpoint, so the form refuses
 * to run without (a) an endpoint on the operator's allow-list, (b) an explicit
 * confirmation, and (c) an acknowledgement that the result will be recorded as
 * a control-efficacy observation. Nothing here is inferred.
 */
export function ProbeRunForm({
  assessmentId,
  library,
  maxTrials,
  onResult,
}: ProbeRunFormProps) {
  const [probeId, setProbeId] = React.useState(library[0]?.id ?? '');
  const [endpoint, setEndpoint] = React.useState('');
  const [model, setModel] = React.useState('');
  const [trials, setTrials] = React.useState(20);
  const [confirm, setConfirm] = React.useState(false);
  const [attribute, setAttribute] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const selected = library.find((p) => p.id === probeId);
  const canRun = probeId && endpoint.trim().length > 0 && confirm && !busy;

  const run = async (dryRun: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const body = {
        probe_id: probeId,
        endpoint: endpoint.trim() || null,
        model: model.trim() || null,
        trials,
        confirm: dryRun ? false : true,
        attribute_to: attribute.trim()
          ? attribute.split(',').map((s) => s.trim()).filter(Boolean)
          : null,
      };
      const r = await postParsed(zProbeRun,
        `/security/assessments/${assessmentId}/probes/run`, body);
      onResult(r as ProbeResult);
    } catch {
      setError('The probe run could not be completed. Check the endpoint and allow-list.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Run a probe</CardTitle>
        <CardDescription>
          Dry run first: it reports what would be sent, and sends nothing.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 text-sm">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Probe" htmlFor="probe-id">
            <select
              id="probe-id"
              value={probeId}
              onChange={(e) => setProbeId(e.target.value)}
              className="w-full rounded-md border bg-background px-2 py-1.5 text-xs"
            >
              {library.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id} — {p.attack_class}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Trials" htmlFor="probe-trials">
            <input
              id="probe-trials"
              type="number"
              min={1}
              max={maxTrials}
              value={trials}
              onChange={(e) =>
                setTrials(Math.min(maxTrials, Math.max(1, Number(e.target.value) || 1)))
              }
              className="w-full rounded-md border bg-background px-2 py-1.5 text-xs tabular"
            />
          </Field>
        </div>

        {selected && (
          <p className="text-xs text-muted-foreground">{selected.description}</p>
        )}

        <Field label="Target endpoint" htmlFor="probe-endpoint"
          hint="Must be on PROBE_ALLOWED_HOSTS. No default — the harness never guesses a target.">
          <input
            id="probe-endpoint"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://your-model-host/v1/chat/completions"
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </Field>

        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Model (optional)" htmlFor="probe-model">
            <input
              id="probe-model"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
            />
          </Field>
          <Field label="Attribute to controls (optional)" htmlFor="probe-attr"
            hint="Comma-separated control ids. The result becomes an efficacy trial for each.">
            <input
              id="probe-attr"
              value={attribute}
              onChange={(e) => setAttribute(e.target.value)}
              placeholder="C02, C03"
              className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
            />
          </Field>
        </div>

        <label className="flex items-start gap-2 rounded-md border p-3 text-xs">
          <input
            type="checkbox"
            checked={confirm}
            onChange={(e) => setConfirm(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            I own this endpoint and am authorised to test it. Running this probe sends
            adversarial payloads and records the outcome as a control-efficacy observation.
          </span>
        </label>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => run(true)} disabled={!probeId || busy}>
            <Lock className="size-3.5" />
            Dry run
          </Button>
          <Button size="sm" onClick={() => run(false)} disabled={!canRun}>
            <Send className="size-3.5" />
            Execute {trials} trial{trials > 1 ? 's' : ''}
          </Button>
          {!confirm && (
            <span className="text-[11px] text-muted-foreground">
              Confirm to enable execution.
            </span>
          )}
        </div>

        {error && <p className="text-xs text-destructive">{error}</p>}
      </CardContent>
    </Card>
  );
}

function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={htmlFor} className="text-xs font-medium">
        {label}
      </label>
      {children}
      {hint && <span className="text-[11px] text-muted-foreground">{hint}</span>}
    </div>
  );
}