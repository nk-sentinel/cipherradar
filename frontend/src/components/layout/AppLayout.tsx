import { Outlet } from '@tanstack/react-router';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

export function AppLayout(): React.ReactElement {
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="content-area">
        <TopBar />
        <Outlet />
      </main>
    </div>
  );
}
