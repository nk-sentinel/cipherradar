import { useParams } from '@tanstack/react-router';
import { ScanHistory } from './ScanHistory.tsx';

export function ScanHistoryPage(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  return <ScanHistory repoId={repoId} />;
}
