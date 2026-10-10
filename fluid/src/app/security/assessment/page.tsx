import { Suspense } from 'react';
import { AssessmentWorkspace } from './assessment-workspace';
import { Skeleton } from '@/components/ui/skeleton';

export const metadata = { title: 'Assessment' };

/**
 * A static export cannot prerender arbitrary assessment ids, so this page is a
 * client-rendered view selected by ?id=. The nav-rail deep link is stable and
 * bookmarkable without a dynamic route.
 */
export default function AssessmentPage() {
  return (
    <Suspense fallback={<Skeleton className="h-52 w-full" />}>
      <AssessmentWorkspace />
    </Suspense>
  );
}
