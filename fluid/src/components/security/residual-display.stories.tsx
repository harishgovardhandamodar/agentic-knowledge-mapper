import type { Story, StoryDefault } from '@ladle/react';
import { ResidualDisplay } from './residual-display';
import {
  SAMPLE_EVIDENCE,
  SAMPLE_RESIDUAL,
  SAMPLE_RESIDUAL_OUTSIDE,
} from '@/lib/fixtures';

export default {
  title: 'Security/ResidualDisplay',
} satisfies StoryDefault;

export const WithInterval: Story = () => (
  <div className="max-w-xl">
    <ResidualDisplay residual={SAMPLE_RESIDUAL} evidence={SAMPLE_EVIDENCE} />
  </div>
);

export const HeadlineOutside: Story = () => (
  <div className="max-w-xl">
    <ResidualDisplay residual={SAMPLE_RESIDUAL_OUTSIDE} />
  </div>
);

export const NoInterval: Story = () => (
  <div className="max-w-xl">
    <ResidualDisplay residual={null} pointWithoutInterval={42} />
  </div>
);

export const Compact: Story = () => (
  <div className="max-w-sm">
    <ResidualDisplay residual={SAMPLE_RESIDUAL} compact />
  </div>
);
