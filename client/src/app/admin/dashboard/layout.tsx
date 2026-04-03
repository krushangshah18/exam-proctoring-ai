'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  LayoutDashboard, Settings, LogOut, FileText, Menu, X, GraduationCap,
} from 'lucide-react';
import { toast } from 'sonner';
import RoleGuard from '@/components/auth/role-guard';
import api from '@/lib/axios';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [user, setUser] = useState<{ full_name?: string; email?: string; must_change_password?: boolean } | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUserProfile = useCallback(async () => {
    try {
      const res = await api.get('/auth/me');
      if (res.data.must_change_password) {
        toast.info('Please set up your new password first.');
        router.push('/auth/setup-password');
        return;
      }
      setUser(res.data);
    } catch (error) {
      console.error('Failed to fetch user profile', error);
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => { fetchUserProfile(); }, [fetchUserProfile]);

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) await api.post('/auth/logout', { refresh_token: refreshToken });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      toast.success('Logged out successfully');
      router.push('/auth/login');
    }
  };

  const navigation = [
    { name: 'Dashboard', href: '/admin/dashboard', icon: LayoutDashboard },
    { name: 'Exams', href: '/admin/dashboard/exams', icon: FileText },
    { name: 'Reports', href: '/admin/dashboard/reports', icon: GraduationCap },
    { name: 'Settings', href: '/admin/dashboard/settings', icon: Settings },
  ];

  const initials = user?.full_name
    ? user.full_name.split(' ').map((n: string) => n[0]).join('').slice(0, 2).toUpperCase()
    : '?';

  const SidebarContent = () => (
    <div className="h-full flex flex-col admin-root" style={{ fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      <style>{`@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');`}</style>

      {/* Logo */}
      <div className="h-16 flex items-center gap-3 px-5" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
        <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0" style={{ background: 'rgba(87,204,153,0.18)' }}>
          <GraduationCap className="h-4 w-4" style={{ color: '#57CC99' }} />
        </div>
        <div>
          <p className="text-sm font-bold leading-none text-white">ProctorAI</p>
          <p className="text-[10px] mt-0.5 font-medium" style={{ color: 'rgba(255,255,255,0.45)' }}>Admin Dashboard</p>
        </div>
      </div>

      {/* Nav items */}
      <nav className="flex-1 py-5 px-3 space-y-0.5 overflow-y-auto">
        {navigation.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/admin/dashboard' && pathname.startsWith(item.href));
          return (
            <Link
              key={item.name}
              href={item.href}
              onClick={() => setIsSidebarOpen(false)}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 relative group"
              style={{
                background: isActive ? 'rgba(255,255,255,0.11)' : 'transparent',
                color: isActive ? '#fff' : 'rgba(255,255,255,0.58)',
                borderLeft: isActive ? '3px solid #57CC99' : '3px solid transparent',
              }}
              onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.06)'; }}
              onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
            >
              <item.icon className="h-4 w-4 shrink-0" style={{ color: isActive ? '#57CC99' : 'rgba(255,255,255,0.45)' }} />
              {item.name}
            </Link>
          );
        })}
      </nav>

      {/* User section */}
      <div className="p-3" style={{ borderTop: '1px solid rgba(255,255,255,0.08)' }}>
        <button
          className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg mb-1.5 transition-all duration-150 text-left"
          style={{ color: 'rgba(255,255,255,0.7)' }}
          onClick={() => router.push('/admin/dashboard/settings')}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.06)'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = 'transparent'}
        >
          <div className="h-8 w-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
            style={{ background: 'rgba(87,204,153,0.18)', color: '#57CC99' }}>
            {initials}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-white truncate">{loading ? 'Loading…' : user?.full_name || 'Admin'}</p>
            <p className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,0.4)' }}>{user?.email}</p>
          </div>
        </button>
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150"
          style={{ color: 'rgba(255,255,255,0.45)' }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLElement).style.color = '#fca5a5';
            (e.currentTarget as HTMLElement).style.background = 'rgba(239,68,68,0.1)';
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLElement).style.color = 'rgba(255,255,255,0.45)';
            (e.currentTarget as HTMLElement).style.background = 'transparent';
          }}
        >
          <LogOut className="h-3.5 w-3.5 shrink-0" />
          Sign out
        </button>
      </div>
    </div>
  );

  return (
    <RoleGuard allowedRoles={['ADMIN']}>
      <div
        className="flex h-screen overflow-hidden"
        style={{ background: '#F8FAFC', fontFamily: "'Plus Jakarta Sans', sans-serif" }}
      >

        {/* Mobile Header */}
        <div className="lg:hidden fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-4 h-13"
          style={{ background: '#22577A', borderBottom: '1px solid rgba(255,255,255,0.08)', height: '52px' }}>
          <div className="flex items-center gap-2">
            <GraduationCap className="h-5 w-5" style={{ color: '#57CC99' }} />
            <span className="text-sm font-bold text-white" style={{ fontFamily: "'Plus Jakarta Sans', sans-serif" }}>ProctorAI</span>
          </div>
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="p-1.5 rounded-lg"
            style={{ color: 'rgba(255,255,255,0.7)' }}>
            {isSidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>

        {/* Mobile overlay */}
        {isSidebarOpen && (
          <div className="lg:hidden fixed inset-0 z-30 bg-black/40" onClick={() => setIsSidebarOpen(false)} />
        )}

        {/* Sidebar */}
        <aside
          className={`fixed inset-y-0 left-0 z-40 w-64 transform transition-transform duration-200 ease-in-out lg:translate-x-0 lg:sticky lg:top-0 lg:h-screen ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'} mt-[52px] lg:mt-0`}
          style={{ background: '#22577A' }}>
          <SidebarContent />
        </aside>

        {/* Main content */}
        <main className="min-w-0 flex-1 mt-[52px] lg:mt-0 overflow-y-auto">
          <div className="p-6 lg:p-8 min-h-full">
            {children}
          </div>
        </main>
      </div>
    </RoleGuard>
  );
}
