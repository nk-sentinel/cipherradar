import { useParams } from '@tanstack/react-router';
import { RepoScans } from './RepoScans.tsx';

export function ScanDetailPage(): React.ReactElement {
  const { scanId } = useParams({ strict: false }) as {
    repoId: string;
    scanId: string;
  };

  return (
    <div>
      <RepoScans scanId={scanId} />
    </div>
  );
}
