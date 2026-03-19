import { NotificationBell } from './NotificationBell';
import { AvatarDropdown } from './AvatarDropdown';

export function TopBar(): React.ReactElement {
  return (
    <div className="topbar">
      <div />
      <div className="topbar-right">
        <NotificationBell />
        <AvatarDropdown />
      </div>
    </div>
  );
}
