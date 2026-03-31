import { Link, Outlet, useLocation } from 'react-router';
import { Activity, LayoutDashboard, LogOut, Package, Shield, UserCheck, UserPlus, Menu, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';

import { useAuth } from '../context/AuthContext';
import { getSystemHealth, SystemHealthResponse } from '../../api/system';
import { handleApiError } from '../../utils/errorHandler';

export default function ReconLayout() {
  const location = useLocation();
  const { logout, user } = useAuth();
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [now, setNow] = useState(new Date());
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const data = await getSystemHealth();
        if (mounted) setHealth(data);
      } catch (error) {
        if (mounted) setHealth(null);
        handleApiError(error);
      }
    };
    void load();
    const id = window.setInterval(load, 60000);
    return () => {
      mounted = false;
      window.clearInterval(id);
    };
  }, []);

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 1000 * 30);
    return () => window.clearInterval(id);
  }, []);

  const statusUi = useMemo(() => {
    const status = health?.status || 'operational';
    if (status === 'down') return { dot: 'bg-red-500', label: 'System Unavailable' };
    if (status === 'degraded') return { dot: 'bg-yellow-500', label: 'Degraded Performance' };
    return { dot: 'bg-green-500', label: 'All Systems Operational' };
  }, [health]);

  const navItems = [
    { path: '/app', label: 'Dashboard', icon: LayoutDashboard },
    { path: '/inventory', label: 'Asset Inventory', icon: Package },
    { path: '/new-scan', label: 'New Scan', icon: Activity },
    ...(user?.role === 'admin'
      ? [
          { path: '/admin/requests', label: 'Admin Requests', icon: UserCheck },
          { path: '/admin/users/new', label: 'Create User', icon: UserPlus },
        ]
      : []),
  ];

  const isActive = (path: string) => {
    if (path === '/app') return location.pathname === '/app';
    return location.pathname.startsWith(path);
  };

  return (
    <div className="min-h-screen aurora-bg text-slate-900 flex flex-col">
      {/* Top Navbar */}
      <header className="glass-surface border-b border-slate-200/70 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            
            {/* Branding */}
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-300 via-teal-400 to-sky-500 flex items-center justify-center shadow-lg glow-ring">
                <Shield className="w-6 h-6 text-slate-950" />
              </div>
              <div className="hidden sm:block">
                <h1 className="text-xl font-bold text-slate-900 font-display">SecureScope</h1>
                <p className="text-[0.65rem] uppercase tracking-[0.3em] text-slate-600 font-semibold mt-0.5">Recon / Attack Surface Scanner</p>
              </div>
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex items-center space-x-1">
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = isActive(item.path);
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`
                      flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200
                      ${active 
                        ? 'bg-emerald-100 text-emerald-800 shadow-sm border border-emerald-200' 
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                      }
                    `}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </Link>
                );
              })}
            </nav>

            {/* User & Settings */}
            <div className="hidden md:flex items-center gap-4 border-l border-slate-200 pl-4 ml-2">
              <div className="text-right flex flex-col items-end">
                <span className="text-sm font-medium text-slate-900">{user?.name || user?.email || 'Guest'}</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <div className={`w-1.5 h-1.5 rounded-full ${statusUi.dot}`}></div>
                  <span className="text-[0.65rem] uppercase text-slate-500 tracking-wider font-semibold">{statusUi.label}</span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => void logout()}
                className="p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors"
                title="Sign out"
              >
                <LogOut className="w-5 h-5" />
              </button>
            </div>

            {/* Mobile Menu Button */}
            <div className="md:hidden flex items-center">
              <button
                type="button"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="p-2 rounded-md text-slate-600 hover:text-slate-900 hover:bg-slate-100 focus:outline-none"
              >
                {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-white/95 border-b border-slate-200 shadow-xl absolute w-full left-0 z-40">
            <div className="px-2 pt-2 pb-3 space-y-1 sm:px-3">
              <div className="px-3 pb-3 pt-1 border-b border-slate-200/70 mb-2">
                <span className="block text-sm font-medium text-slate-900">{user?.name || user?.email || 'Guest'}</span>
                <span className="block text-xs font-medium text-slate-600">{user?.role === 'admin' ? 'Administrator' : 'User'}</span>
              </div>
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = isActive(item.path);
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`
                      flex items-center gap-3 px-3 py-2 rounded-md text-base font-medium
                      ${active 
                        ? 'bg-emerald-100 text-emerald-800' 
                        : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100'
                      }
                    `}
                  >
                    <Icon className="w-5 h-5" />
                    {item.label}
                  </Link>
                );
              })}
              <button
                type="button"
                onClick={() => { setMobileMenuOpen(false); void logout(); }}
                className="w-full flex items-center gap-3 px-3 py-2 mt-4 rounded-md text-base font-medium text-red-400 hover:text-red-300 hover:bg-slate-100"
              >
                <LogOut className="w-5 h-5" />
                Sign out
              </button>
            </div>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative">
        <Outlet />
      </main>
      
      {/* Footer */}
      <footer className="border-t border-slate-200/70 bg-white/70 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between text-xs text-slate-500">
          <p>&copy; {new Date().getFullYear()} SecureScope Platform</p>
          <p>Local Time: {now.toLocaleString()}</p>
        </div>
      </footer>
    </div>
  );
}

