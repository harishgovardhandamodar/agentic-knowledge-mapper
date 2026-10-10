/**
 * Representative sample data for the foundation slice.
 *
 * The claim-verification engine (app/claims.py) is not yet exposed over HTTP,
 * so the Claims workspace and the Ladle stories render these fixtures. They are
 * shaped exactly like the adapter output (lib/api/adapters.ts) so wiring a real
 * endpoint later is a swap, not a rewrite. Every screen that uses them says so.
 */
import type { Claim, ResidualInterval } from '@/types/domain';

export const SAMPLE_SOURCE_TEXT: Record<string, string> = {
  'src:arxiv-2411':
    'Retrieval-augmented generation reduces hallucination by grounding every answer in ' +
    'a cited passage. The system must not emit a claim whose citation cannot be resolved ' +
    'to a retrieved span. Evaluation on 1,200 questions showed a 38% reduction in ' +
    'unsupported statements, though the effect shrinks to 11% on questions requiring ' +
    'multi-hop reasoning.',
  'src:blog-vendor':
    'Our platform provides enterprise-grade security for every deployment. All data is ' +
    'encrypted at rest and in transit, and the system is certified to ISO 27001.',
};

export const SAMPLE_CLAIMS: Claim[] = [
  {
    id: 'clm_a1b2c3d4e5',
    text: 'Retrieval grounding reduced unsupported statements by 38% on single-hop questions.',
    verdict: 'supported',
    support: 0.82,
    confidence: 0.78,
    confidenceInterval: [0.63, 0.9],
    evidenceStatus: 'direct',
    review: 'accepted',
    spans: [
      {
        sourceId: 'src:arxiv-2411',
        quote: 'a 38% reduction in unsupported statements',
        start: 224,
        end: 265,
        verifiedBy: 'verbatim',
        status: 'direct',
      },
    ],
    sources: [
      { id: 'src:arxiv-2411', title: 'Grounding for RAG', domain: 'arxiv.org' },
    ],
    tensions: [],
    threatId: 'T03',
    investigationId: 1,
  },
  {
    id: 'clm_f6g7h8i9j0',
    text: 'The platform is certified to ISO 27001.',
    verdict: 'weak',
    support: 0.41,
    confidence: 0.34,
    confidenceInterval: [0.2, 0.52],
    evidenceStatus: 'modality',
    review: 'needs_evidence',
    spans: [
      {
        sourceId: 'src:blog-vendor',
        quote: 'certified to ISO 27001',
        start: 134,
        end: 156,
        verifiedBy: 'verbatim',
        status: 'modality',
      },
    ],
    sources: [{ id: 'src:blog-vendor', title: 'Vendor security page', domain: 'vendor.example' }],
    tensions: [],
    investigationId: 1,
  },
  {
    id: 'clm_k1l2m3n4o5',
    text: 'Grounding removes hallucination entirely.',
    verdict: 'contradicted',
    support: 0.12,
    confidence: 0.09,
    confidenceInterval: [0.03, 0.2],
    evidenceStatus: 'contradicts',
    review: 'rejected',
    spans: [
      {
        sourceId: 'src:arxiv-2411',
        quote: 'the effect shrinks to 11% on questions requiring multi-hop reasoning',
        start: 274,
        end: 342,
        verifiedBy: 'entailment',
        status: 'contradicts',
      },
    ],
    sources: [{ id: 'src:arxiv-2411', title: 'Grounding for RAG', domain: 'arxiv.org' }],
    tensions: [
      {
        id: 'clm_a1b2c3d4e5~clm_k1l2m3n4o5',
        kind: 'contradicts',
        againstClaimId: 'clm_a1b2c3d4e5',
        againstText: 'Retrieval grounding reduced unsupported statements by 38% on single-hop questions.',
        terms: ['grounding', 'hallucination', 'reduction'],
        note: 'shares: grounding, hallucination, reduction',
      },
    ],
    investigationId: 1,
  },
  {
    id: 'clm_p6q7r8s9t0',
    text: 'The system guarantees zero unsupported output.',
    verdict: 'unsupported',
    support: 0.05,
    evidenceStatus: 'absent',
    review: 'unreviewed',
    spans: [],
    sources: [],
    tensions: [],
    inventedCitations: ['src:does-not-exist'],
    investigationId: 1,
  },
];

export const SAMPLE_RESIDUAL: ResidualInterval = {
  point: 42,
  lower: 31,
  upper: 58,
  level: 0.9,
  headlineInside: true,
  nThreats: 12,
};

export const SAMPLE_RESIDUAL_OUTSIDE: ResidualInterval = {
  point: 67,
  lower: 22,
  upper: 44,
  level: 0.9,
  headlineInside: false,
  nThreats: 9,
};

export const SAMPLE_EVIDENCE = {
  direct: 5,
  family: 3,
  modality: 2,
  absent: 2,
} as const;
