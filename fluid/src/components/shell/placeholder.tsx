import type { LucideIcon } from 'lucide-react';
import { PageHeader } from '@/components/shell/page-header';
import { Card, CardContent } from '@/components/ui/card';

/**
 * An honest "not in this slice" screen. It states what the surface will do and
 * that it is not built yet, rather than showing a broken or fake workspace.
 */
export function Placeholder({
  title,
  description,
  icon: Icon,
  planned,
}: {
  title: string;
  description: string;
  icon: LucideIcon;
  planned: string[];
}) {
  return (
    <div>
      <PageHeader title={title} description={description} />
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
          <Icon className="size-8 text-muted-foreground" aria-hidden />
          <p className="text-sm font-medium">Not in this foundation slice yet</p>
          <ul className="max-w-md list-inside list-disc text-left text-xs text-muted-foreground">
            {planned.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
