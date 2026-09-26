import React, { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({ startOnLoad: false, theme: 'dark', themeVariables: { primaryColor: '#4da3ff', lineColor: '#9fb0c0', textColor: '#e8eef4', mainBkg: '#171e26', tertiaryColor: '#0c1117' } });

export default function Mermaid({ code }: { code: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const idRef = useRef(`m-${Math.random().toString(36).slice(2, 9)}`);

  useEffect(() => {
    if (!ref.current) return;
    // mermaid.render returns SVG string (v10+)
    mermaid.render(idRef.current, code).then(({ svg }) => {
      if (ref.current) ref.current.innerHTML = svg;
    }).catch(() => {
      // fallback: show code
      if (ref.current) ref.current.textContent = code;
    });
  }, [code]);

  return <div ref={ref} style={{ background: '#0c1117', border: '1px solid #26303c', borderRadius: 8, padding: 8, overflow: 'auto' }} />;
}
