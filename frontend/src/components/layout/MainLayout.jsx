import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

export default function MainLayout() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <Sidebar />
      <div style={{ flex: 1, marginLeft: 240, display: 'flex', flexDirection: 'column' }}>
        <Header />
        {/* Authorization Banner */}
        <div style={{
          background: 'rgba(245, 158, 11, 0.08)',
          borderBottom: '1px solid rgba(245, 158, 11, 0.2)',
          padding: '0.375rem 1.5rem',
          fontSize: '0.6875rem',
          color: '#f59e0b',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <span>⚠</span>
          This framework is intended for authorized security testing, academic research, and controlled laboratory environments only.
        </div>
        <main style={{
          flex: 1,
          padding: '1.5rem',
          overflowY: 'auto',
          maxHeight: 'calc(100vh - 64px - 30px)',
        }}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
