export interface ProbeRate {
  successes: number;
  trials: number;
  rate: number | null;
  lower: number | null;
  upper: number | null;
  method?: string;
  note?: string;
}

export interface ProbeScore {
  experiment_id?: string;
  method_type?: string;
  rate: ProbeRate;
  verdict: string;
  conclusion: string;
  minimum_trials_for_power: number;
  recommended_next_trials: number;
  note: string;
}

export interface ProbeAttempt {
  trial: number;
  http_status: number;
  hit: boolean;
  elapsed_s: number;
  excerpt: string;
}

export interface ProbeProvenance {
  control_id: string;
  basis: string;
  validated: boolean;
  n_observations: number;
  n_held: number;
  n_breached: number;
  posterior_mean: number | null;
}

export interface ProbeResult {
  probe_id: string;
  attack_class?: string;
  status: 'skipped' | 'completed' | 'unreachable';
  reason?: string | null;
  trials_requested: number;
  successes?: number;
  endpoint_host?: string;
  would_send?: { endpoint_host?: string; trials: number };
  attempts?: ProbeAttempt[];
  score?: ProbeScore;
  efficacy_provenance?: ProbeProvenance[];
}