import type { Story, StoryDefault } from '@ladle/react';
import { EvidenceSpanViewer } from './evidence-span-viewer';
import { SAMPLE_CLAIMS, SAMPLE_SOURCE_TEXT } from '@/lib/fixtures';

export default {
  title: 'Claims/EvidenceSpanViewer',
} satisfies StoryDefault;

const sourceText = (id: string) => SAMPLE_SOURCE_TEXT[id];

export const WithContext: Story = () => (
  <div className="max-w-2xl">
    <EvidenceSpanViewer claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />
  </div>
);

export const NoOffsets: Story = () => (
  <div className="max-w-2xl">
    <EvidenceSpanViewer claim={SAMPLE_CLAIMS[0]!} />
  </div>
);

export const NoEvidence: Story = () => (
  <div className="max-w-2xl">
    <EvidenceSpanViewer claim={SAMPLE_CLAIMS[3]!} sourceText={sourceText} />
  </div>
);
