import { Suspense, lazy } from 'react';

const DependencyGraph = lazy(() =>
  import('./DependencyGraph.tsx').then((mod) => ({ default: mod.DependencyGraph })),
);

export function LazyDependencyGraph(): React.ReactElement {
  return (
    <Suspense
      fallback={
        <div className="card">
          <p style={{ color: 'var(--text-2)', fontSize: '13px' }}>Loading dependency graph...</p>
        </div>
      }
    >
      <DependencyGraph />
    </Suspense>
  );
}
