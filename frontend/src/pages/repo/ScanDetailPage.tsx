import { useParams, Link } from '@tanstack/react-router';
import { RepoScans } from './RepoScans.tsx';

export function ScanDetailPage(): React.ReactElement {
  const { repoId, scanId } = useParams({ strict: false }) as {
    repoId: string;
    scanId: string;
  };

  return (
    <div>
      <div className="breadcrumb">
        <Link to="/repos">Repositories</Link>
        <span>/</span>
        <Link to="/repos/$repoId/overview" params={{ repoId }}>
          {repoId}
        </Link>
        <span>/</span>
        <Link to="/repos/$repoId/scans" params={{ repoId }}>
          Scans
        </Link>
        <span>/</span>
        <strong>{scanId}</strong>
      </div>
      <RepoScans scanId={scanId} />
    </div>
  );
}
