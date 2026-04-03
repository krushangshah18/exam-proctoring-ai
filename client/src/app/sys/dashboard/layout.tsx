'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  LayoutDashboard, Users, Settings, LogOut, Shield,
  FileText, User, Menu, X, SlidersHorizontal, Cpu,
  Activity, BarChart2, PanelLeftClose, PanelLeftOpen,
} from 'lucide-react';
import { toast } from 'sonner';
import RoleGuard from '@/components/auth/role-guard';
import api from '@/lib/axios';

const NAV = [
  { name: 'Overview',         href: '/sys/dashboard',                 icon: LayoutDashboard },
  { name: 'Applications',     href: '/sys/dashboard/applications',    icon: FileText        },
  { name: 'Users',            href: '/sys/dashboard/users',           icon: Users           },
  { name: 'Engine Monitor',   href: '/sys/dashboard/engine',          icon: Cpu             },
  { name: 'Model Tuning',     href: '/sys/dashboard/model-tuning',    icon: SlidersHorizontal },
  { name: 'Live Sessions',    href: '/sys/dashboard/sessions',        icon: Activity        },
  { name: 'Reports',          href: '/sys/dashboard/reports',         icon: BarChart2       },
  { name: 'Engine Settings',  href: '/sys/dashboard/system-settings', icon: SlidersHorizontal },
  { name: 'My Settings',      href: '/sys/dashboard/settings',        icon: Settings        },
];

export default function SystemAdminLayout({ children }: { children: React.ReactNode }) {
  const router   = useRouter();
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [user, setUser]     = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/auth/me')
      .then(r => {
        if (r.data.must_change_password) {
          toast.info('Please set up your new password first.');
          router.push('/auth/setup-password');
          return;
        }
        setUser(r.data);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleLogout = async () => {
    try {
      const rt = localStorage.getItem('refresh_token');
      if (rt) await api.post('/auth/logout', { refresh_token: rt });
    } catch {}
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    toast.success('Signed out');
    router.push('/auth/login');
  };

  const isActive = (href: string) =>
    href === '/sys/dashboard'
      ? pathname === href
      : pathname === href || pathname.startsWith(href + '/');

  return (
    <RoleGuard allowedRoles={['SYSADMIN']}>
      {/* Google Font */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');
        .sys-root { font-family: 'Plus Jakarta Sans', system-ui, sans-serif; }
        .nav-scrollbar::-webkit-scrollbar { width: 0; }
      `}</style>

      <div className="sys-root min-h-screen bg-[#EEF2F7] lg:flex">

        {/* ── Mobile top bar ──────────────────────────────────────── */}
        <div className="lg:hidden fixed top-0 inset-x-0 z-50 h-13 flex items-center justify-between px-4 py-3"
          style={{ background: '#22577A', borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="flex items-center gap-2.5">
            <Shield className="h-5 w-5" style={{ color: '#57CC99' }} />
            <span className="font-bold text-white text-sm tracking-tight">ProctorAI</span>
            <span className="text-[10px] font-medium tracking-widest uppercase" style={{ color: 'rgba(255,255,255,0.55)' }}>Console</span>
          </div>
          <button onClick={() => setSidebarOpen(v => !v)} className="p-1 rounded-lg transition-colors" style={{ color: 'rgba(255,255,255,0.65)' }}>
            {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

        {/* ── Mobile overlay ──────────────────────────────────────── */}
        {sidebarOpen && (
          <div className="lg:hidden fixed inset-0 z-30 bg-black/30 backdrop-blur-sm"
            style={{ top: 52 }} onClick={() => setSidebarOpen(false)} />
        )}

        {/* ── Sidebar ─────────────────────────────────────────────── */}
        <aside
          className={`nav-scrollbar fixed left-0 z-40 flex flex-col transition-[width,transform] duration-300 ease-in-out lg:sticky lg:top-0 lg:h-screen ${
            sidebarCollapsed ? 'lg:w-20' : 'lg:w-64'
          } ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } top-[52px] h-[calc(100vh-52px)] w-64 lg:translate-x-0 lg:top-0`}
          style={{ background: '#22577A', borderRight: '1px solid rgba(255,255,255,0.06)' }}
        >
          {/* Brand */}
          <div className={`hidden lg:flex h-16 items-center shrink-0 ${sidebarCollapsed ? 'justify-center px-3' : 'justify-between px-5'}`}
            style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
            <div className={`flex items-center ${sidebarCollapsed ? 'justify-center' : 'gap-2.5'}`}>
              <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
                style={{ background: 'rgba(87,204,153,0.15)' }}>
                <Shield className="h-4 w-4" style={{ color: '#57CC99' }} />
              </div>
              {!sidebarCollapsed && (
                <div>
                  <p className="text-white font-bold text-sm tracking-tight leading-none">ProctorAI</p>
                  <p className="text-[10px] font-medium tracking-widest uppercase leading-none mt-1"
                    style={{ color: 'rgba(255,255,255,0.55)' }}>System Console</p>
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={() => setSidebarCollapsed(v => !v)}
              className="h-8 w-8 rounded-lg flex items-center justify-center transition-colors"
              style={{ color: 'rgba(255,255,255,0.6)' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.08)'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
              aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            >
              {sidebarCollapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
            </button>
          </div>

          {/* Nav label */}
          <div className={`shrink-0 ${sidebarCollapsed ? 'px-3 pt-5 pb-1' : 'px-5 pt-6 pb-2'}`}>
            {sidebarCollapsed ? (
              <div className="mx-auto h-px w-8" style={{ background: 'rgba(255,255,255,0.12)' }} />
            ) : (
              <p className="text-[10px] font-semibold tracking-widest uppercase"
                style={{ color: 'rgba(255,255,255,0.45)' }}>Menu</p>
            )}
          </div>

          {/* Nav items */}
          <nav className="flex-1 overflow-y-auto nav-scrollbar px-3 space-y-0.5 pb-2">
            {NAV.map(item => {
              const active = isActive(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setSidebarOpen(false)}
                  className={`group relative flex items-center rounded-lg text-sm font-medium transition-all duration-150 ${
                    sidebarCollapsed ? 'justify-center px-2 py-3' : 'gap-3 px-3 py-2.5'
                  }`}
                  style={{
                    color: active ? '#ffffff' : 'rgba(255,255,255,0.58)',
                    background: active ? 'rgba(255,255,255,0.11)' : 'transparent',
                  }}
                  onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.06)'; }}
                  onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
                >
                  {/* Active indicator */}
                  {active && (
                    <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full"
                      style={{ background: '#57CC99' }} />
                  )}
                  <item.icon className="h-4 w-4 shrink-0 transition-colors"
                    style={{ color: active ? '#57CC99' : 'rgba(255,255,255,0.45)' }} />
                  {!sidebarCollapsed && <span>{item.name}</span>}
                </Link>
              );
            })}
          </nav>

          {/* User section */}
          <div className={`shrink-0 space-y-3 ${sidebarCollapsed ? 'p-3' : 'p-4'}`}
            style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
            <div className={`flex items-center ${sidebarCollapsed ? 'justify-center px-0' : 'gap-3 px-1'}`}>
              <div className="h-7 w-7 rounded-full flex items-center justify-center shrink-0"
                style={{ background: 'rgba(255,255,255,0.10)' }}>
                <User className="h-3.5 w-3.5" style={{ color: 'rgba(255,255,255,0.55)' }} />
              </div>
              {!sidebarCollapsed && (
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-white truncate leading-tight">
                    {loading ? '…' : user?.full_name || 'Admin'}
                  </p>
                  <p className="text-[11px] truncate leading-tight" style={{ color: 'rgba(255,255,255,0.55)' }}>
                    {user?.email}
                  </p>
                </div>
              )}
            </div>
            <button
              onClick={handleLogout}
              className={`w-full flex items-center rounded-lg text-sm font-medium transition-all duration-150 ${
                sidebarCollapsed ? 'justify-center px-2 py-2.5' : 'gap-2.5 px-3 py-2'
              }`}
              style={{ color: 'rgba(255,255,255,0.45)' }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.cssText += 'color:#fca5a5;background:rgba(239,68,68,0.1)'; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = 'rgba(255,255,255,0.45)'; (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
            >
              <LogOut className="h-3.5 w-3.5 shrink-0" />
              {!sidebarCollapsed && 'Sign out'}
            </button>
          </div>
        </aside>

        {/* ── Main content ─────────────────────────────────────────── */}
        <main className="min-w-0 flex-1 mt-[52px] lg:mt-0"
          style={{ background: '#EEF2F7' }}>
          <div className="min-h-screen p-6 lg:p-8">
            {children}
          </div>
        </main>
      </div>
    </RoleGuard>
  );
}
