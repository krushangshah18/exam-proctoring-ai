'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { 
  LayoutDashboard, 
  Users, 
  Settings, 
  LogOut, 
  Shield, 
  FileText,
  User,
  Menu,
  X
} from 'lucide-react';
import { toast } from 'sonner';

import RoleGuard from '@/components/auth/role-guard';
import { Button } from '@/components/ui/button';
import api from '@/lib/axios';

export default function SystemAdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const res = await api.get('/auth/me');
      setUser(res.data);
    } catch (error) {
      console.error('Failed to fetch user profile', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (refreshToken) {
        await api.post('/auth/logout', { refresh_token: refreshToken });
      }
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
    { name: 'Dashboard', href: '/sys/dashboard', icon: LayoutDashboard },
    { name: 'Applications', href: '/sys/dashboard/applications', icon: FileText },
    { name: 'Users', href: '/sys/dashboard/users', icon: Users },
    { name: 'Settings', href: '/sys/dashboard/settings', icon: Settings },
  ];

  return (
    <RoleGuard allowedRoles={['SYSADMIN']}>
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex">
        
        {/* Mobile Header */}
        <div className="lg:hidden fixed top-0 left-0 right-0 z-50 flex items-center justify-between p-4 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-blue-600" />
            <span className="font-bold text-lg">SysAdmin</span>
          </div>
          <Button variant="ghost" size="icon" onClick={() => setIsSidebarOpen(!isSidebarOpen)}>
            {isSidebarOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
          </Button>
        </div>

        {/* Sidebar */}
        <aside className={`
          fixed inset-y-0 left-0 z-40 w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 transform transition-transform duration-200 ease-in-out lg:translate-x-0 lg:static lg:h-screen lg:inset-auto
          ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
          mt-16 lg:mt-0 
        `}>
          <div className="h-full flex flex-col">
            <div className="h-16 hidden lg:flex items-center px-6 border-b border-gray-200 dark:border-gray-700">
              <Shield className="h-6 w-6 text-blue-600 mr-2" />
              <span className="font-bold text-xl">SysAdmin</span>
            </div>

            <div className="flex-1 py-6 px-4 space-y-1 overflow-y-auto">
              {navigation.map((item) => {
                const isActive = pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    onClick={() => setIsSidebarOpen(false)}
                    className={`flex items-center px-4 py-3 text-sm font-medium rounded-md transition-colors ${
                      isActive
                        ? 'bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-200'
                        : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700'
                    }`}
                  >
                    <item.icon className="h-5 w-5 mr-3" />
                    {item.name}
                  </Link>
                );
              })}
            </div>

            <div className="p-4 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center gap-3 mb-4 px-2">
                <div className="h-8 w-8 rounded-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center">
                  <User className="h-4 w-4 text-gray-500" />
                </div>
                <div className="flex-1 overflow-hidden">
                  <p className="text-sm font-medium truncate">
                    {loading ? 'Loading...' : user?.full_name || 'Admin'}
                  </p>
                  <p className="text-xs text-muted-foreground truncate">
                    {user?.email}
                  </p>
                </div>
              </div>
              <Button variant="outline" className="w-full justify-start text-red-600 hover:text-red-700 hover:bg-red-50 border-red-200 dark:border-red-900/50" onClick={handleLogout}>
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-8 mt-16 lg:mt-0">
          {children}
        </main>
      </div>
    </RoleGuard>
  );
}
