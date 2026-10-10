import type { Config } from 'tailwindcss';
import animate from 'tailwindcss-animate';

// Dark-first research aesthetic (see the GUI brief §2). Semantic tokens live in
// CSS variables so severity and uncertainty colours are never hard-coded in a
// component — the one rule the brief repeats. shadcn/ui reads the same
// variables, so its primitives inherit the theme for free.
const config: Config = {
  darkMode: ['class'],
  content: [
    './src/**/*.{ts,tsx,mdx}',
    './.ladle/**/*.{ts,tsx}',
  ],
  theme: {
    container: {
      center: true,
      padding: '1.5rem',
      screens: { '2xl': '1536px' },
    },
    extend: {
      fontFamily: {
        sans: ['var(--font-sans)', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
        // Severity bands. Named by meaning, never pure red/green so colour-blind
        // readers keep the signal (§2). Each also carries a glyph in the UI.
        severity: {
          critical: 'hsl(var(--severity-critical))',
          high: 'hsl(var(--severity-high))',
          medium: 'hsl(var(--severity-medium))',
          low: 'hsl(var(--severity-low))',
          info: 'hsl(var(--severity-info))',
        },
        // Evidence status of a claim (direct → absent). Backed by the
        // uncertainty module's EVIDENCE_STATUSES.
        evidence: {
          direct: 'hsl(var(--evidence-direct))',
          family: 'hsl(var(--evidence-family))',
          modality: 'hsl(var(--evidence-modality))',
          absent: 'hsl(var(--evidence-absent))',
          contradicts: 'hsl(var(--evidence-contradicts))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      keyframes: {
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
      },
      animation: {
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
      },
    },
  },
  plugins: [animate],
};

export default config;
