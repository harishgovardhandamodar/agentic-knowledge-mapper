import { Users } from 'lucide-react';
import { Placeholder } from '@/components/shell/placeholder';

export const metadata = { title: 'Manager' };

export default function ManagerPage() {
  return (
    <Placeholder
      title="Manager"
      description="Review queue and stewardship."
      icon={Users}
      planned={[
        'Accept / reject / needs-evidence review actions',
        'Vendor questionnaire and assurance register',
        'Evidence-pack export with ledger integrity',
      ]}
    />
  );
}
