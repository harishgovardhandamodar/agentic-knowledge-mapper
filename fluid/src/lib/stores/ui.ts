/**
 * UI state that is not server data: which investigation and assessment are in
 * focus, and the shell's nav behaviour. Server data lives in TanStack Query;
 * this store holds only what the URL would otherwise have to carry.
 *
 * The selection is persisted so a reload keeps the researcher where they were,
 * and the URL remains the deep-link source of truth for a specific assessment.
 */
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface UiState {
  /** Investigation currently in focus across the whole shell. */
  investigationId: number | null;
  /** Assessment in focus within the security workspace. */
  assessmentId: number | null;
  /** Nav rail collapsed to icons (dense research layouts). */
  navCollapsed: boolean;
  /** Command palette open state. */
  paletteOpen: boolean;

  setInvestigation: (id: number | null) => void;
  setAssessment: (id: number | null) => void;
  toggleNav: () => void;
  setPalette: (open: boolean) => void;
  reset: () => void;
}

export const useUi = create<UiState>()(
  persist(
    (set) => ({
      investigationId: null,
      assessmentId: null,
      navCollapsed: false,
      paletteOpen: false,

      setInvestigation: (id) =>
        set((s) =>
          s.investigationId === id ? s : { investigationId: id, assessmentId: null },
        ),
      setAssessment: (id) => set({ assessmentId: id }),
      toggleNav: () => set((s) => ({ navCollapsed: !s.navCollapsed })),
      setPalette: (open) => set({ paletteOpen: open }),
      reset: () => set({ investigationId: null, assessmentId: null }),
    }),
    {
      name: 'akm-fluid-ui',
      partialize: (s) => ({
        investigationId: s.investigationId,
        assessmentId: s.assessmentId,
        navCollapsed: s.navCollapsed,
      }),
    },
  ),
);
