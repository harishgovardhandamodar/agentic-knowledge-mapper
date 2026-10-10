/**
 * The nav-rail model. One array drives the rail, the command palette and the
 * breadcrumb labels, so a route is added in exactly one place.
 *
 * `built` marks the surfaces that exist in this foundation slice; the rest are
 * listed so the shape of the product is visible, but their pages are honest
 * placeholders rather than fake screens.
 */
import type { LucideIcon } from 'lucide-react';
import {
  Shield,
  FileText,
  Network,
  LayoutDashboard,
  Terminal,
  Users,
  Palette,
  Lock,
  Home,
  Gauge,
  Compass,
  FileOutput,
  FlaskConical,
} from 'lucide-react';

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Short purpose, shown in the palette and as a tooltip when collapsed. */
  hint: string;
  built: boolean;
  group: 'workspace' | 'analysis' | 'system';
}

export const NAV_ITEMS: NavItem[] = [
  { href: '/', label: 'Overview', icon: Home, hint: 'Current investigation at a glance', built: true, group: 'workspace' },
  { href: '/mapper', label: 'Mapper', icon: Network, hint: 'Knowledge graph of the investigation', built: false, group: 'workspace' },
  { href: '/claims', label: 'Claims', icon: FileText, hint: 'Atomic claims and their evidence spans', built: true, group: 'workspace' },
  { href: '/security', label: 'Security', icon: Shield, hint: 'Threat assessments and residuals', built: true, group: 'analysis' },
  { href: '/calibration', label: 'Calibration', icon: Gauge, hint: 'Score saturation, efficacy provenance, variance budget', built: true, group: 'analysis' },
  { href: '/gaps', label: 'Gaps', icon: Compass, hint: 'Open questions and unasked areas', built: true, group: 'analysis' },
  { href: '/probes', label: 'Probes', icon: FlaskConical, hint: 'Run adversarial probes and record efficacy trials', built: true, group: 'analysis' },
  { href: '/scenarios', label: 'Scenarios', icon: Network, hint: 'Attack paths derived from control gaps', built: true, group: 'analysis' },
  { href: '/experiments', label: 'Experiments', icon: FlaskConical, hint: 'Planned tests for what is still open', built: true, group: 'analysis' },
  { href: '/report', label: 'Report', icon: FileOutput, hint: 'Exportable research report with its limitations', built: true, group: 'analysis' },
  { href: '/privacy', label: 'Privacy', icon: Lock, hint: 'External-reach budget and erasure', built: true, group: 'analysis' },
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, hint: 'Cross-investigation metrics', built: false, group: 'analysis' },
  { href: '/manager', label: 'Manager', icon: Users, hint: 'Review queue and stewardship', built: false, group: 'system' },
  { href: '/console', label: 'Console', icon: Terminal, hint: 'Runs, logs and reproducibility manifests', built: false, group: 'system' },
  { href: '/design', label: 'Design', icon: Palette, hint: 'Tokens and component gallery', built: true, group: 'system' },
];

export const NAV_GROUPS: { id: NavItem['group']; label: string }[] = [
  { id: 'workspace', label: 'Workspace' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'system', label: 'System' },
];
