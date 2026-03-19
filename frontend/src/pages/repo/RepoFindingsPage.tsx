import { useParams } from '@tanstack/react-router';
import { RepoFindings } from './RepoFindings.tsx';

export function RepoFindingsPage(): React.ReactElement {
  const { repoId } = useParams({ strict: false }) as { repoId: string };
  return <RepoFindings repoId={repoId} />;
}
