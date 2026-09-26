import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';
import type { Dimension, IngestedData } from './lib/engine';
import type { GraphData } from './lib/graph';
import generated from '../public/data.json';
import graphJson from '../public/graph.json';
import taxonomy from '../data/taxonomy.json';

// Trust boundary: these files are written by scripts/ingest.mjs (validated
// coverage scores 0|1|2, known dimensions), so their shapes are asserted once here.
const cert = generated as unknown as Partial<IngestedData> & { dimensions?: Dimension[] };
const tax = taxonomy as { dimensions?: Dimension[] };
const graph = (graphJson as unknown as GraphData) ?? null;

const data: IngestedData = {
  generated: cert.generated ?? new Date().toISOString().slice(0, 10),
  dimensions: tax.dimensions ?? cert.dimensions ?? [],
  frameworks: cert.frameworks ?? [],
  overlap: cert.overlap ?? [],
};

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App data={data} graph={graph} />
  </React.StrictMode>,
);