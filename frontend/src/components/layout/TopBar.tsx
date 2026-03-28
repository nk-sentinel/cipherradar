import { Breadcrumbs } from './Breadcrumbs';
import { NotificationBell } from './NotificationBell';
import { AvatarDropdown } from './AvatarDropdown';

export function TopBar(): React.ReactElement {
  return (
    <div className="topbar" style={{ minHeight: '40px' }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Breadcrumbs />
      </div>
      <div className="topbar-right">
        <NotificationBell />
        <AvatarDropdown />
      </div>
    </div>
  );
}
