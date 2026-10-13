import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithProviders as render } from '@/test/render';
import { LlmFallbackNotice, gatewayHost } from './llm-fallback-banner';

describe('LlmFallbackNotice', () => {
  it('renders nothing while the preferred gateway is serving', () => {
    const { container } = render(
      <LlmFallbackNotice
        llm={{ fallback_active: false, served_by: 'http://axiom.tailb61a66.ts.net:8210/v1' }}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when there is no health data', () => {
    const { container } = render(<LlmFallbackNotice />);
    expect(container).toBeEmptyDOMElement();
  });

  it('warns and names both gateways when the fallback is serving', () => {
    render(
      <LlmFallbackNotice
        llm={{
          fallback_active: true,
          preferred_url: 'http://axiom.tailb61a66.ts.net:8210/v1',
          served_by: 'http://axiom-dgx.tailb61a66.ts.net:8210/v1',
          notice: 'LLM calls are being served by the fallback gateway',
        }}
      />,
    );
    const banner = screen.getByRole('status');
    expect(banner).toHaveTextContent(/fallback in use/i);
    expect(banner).toHaveTextContent('axiom-dgx.tailb61a66.ts.net:8210');
    expect(banner).toHaveTextContent('axiom.tailb61a66.ts.net:8210');
  });

  it('derives host[:port] from a base URL', () => {
    expect(gatewayHost('http://axiom.tailb61a66.ts.net:8210/v1')).toBe(
      'axiom.tailb61a66.ts.net:8210',
    );
    expect(gatewayHost(null)).toBe('unknown');
  });
});
