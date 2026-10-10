import type { Story, StoryDefault } from '@ladle/react';
import { ClaimCard } from './claim-card';
import { SAMPLE_CLAIMS, SAMPLE_SOURCE_TEXT } from '@/lib/fixtures';

export default {
  title: 'Claims/ClaimCard',
} satisfies StoryDefault;

const sourceText = (id: string) => SAMPLE_SOURCE_TEXT[id];

export const Supported: Story = () => (
  <div className="max-w-2xl">
    <ClaimCard claim={SAMPLE_CLAIMS[0]!} sourceText={sourceText} />
  </div>
);

export const Weak: Story = () => (
  <div className="max-w-2xl">
    <ClaimCard claim={SAMPLE_CLAIMS[1]!} sourceText={sourceText} />
  </div>
);

export const Contradicted: Story = () => (
  <div className="max-w-2xl">
    <ClaimCard claim={SAMPLE_CLAIMS[2]!} sourceText={sourceText} defaultExpanded />
  </div>
);

export const Unsupported: Story = () => (
  <div className="max-w-2xl">
    <ClaimCard claim={SAMPLE_CLAIMS[3]!} sourceText={sourceText} />
  </div>
);
