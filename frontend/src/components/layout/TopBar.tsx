import { Breadcrumbs } from './Breadcrumbs';
import { NotificationBell } from './NotificationBell';
import { AvatarDropdown } from './AvatarDropdown';

export function TopBar(): React.ReactElement {
  return (
    <div className="topbar">
      <Breadcrumbs />
      <div className="topbar-right">
        <NotificationBell />
        <AvatarDropdown />
      </div>
    </div>
  );
}
