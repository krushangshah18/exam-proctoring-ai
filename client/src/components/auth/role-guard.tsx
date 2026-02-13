'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { jwtDecode } from 'jwt-decode';

interface RoleGuardProps {
  children: React.ReactNode;
  allowedRoles: string[];
}

interface JWTPayload {
  sub: string;
  role: string;
  exp: number;
}

export default function RoleGuard({ children, allowedRoles }: RoleGuardProps) {
  const router = useRouter();
  const [authorized, setAuthorized] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem('access_token');

    if (!token) {
      router.push('/auth/login');
      return;
    }

    try {
      const decoded = jwtDecode<JWTPayload>(token);
      const currentTime = Date.now() / 1000;

      if (decoded.exp < currentTime) {
        // Token expired
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        router.push('/auth/login');
        return;
      }

      if (!allowedRoles.includes(decoded.role)) {
        // Redirect to user's appropriate dashboard based on their role
        if (decoded.role === 'STUDENT') {
          router.push('/student/dashboard');
        } else if (decoded.role === 'ADMIN') {
          router.push('/admin/dashboard');
        } else if (decoded.role === 'SYSADMIN') {
          router.push('/sys/dashboard');
        } else {
          // Fallback to login if role is unknown
          router.push('/auth/login');
        }
        return;
      }

      setAuthorized(true);

    } catch (error) {
      // Invalid token
      localStorage.removeItem('access_token');
      router.push('/auth/login');
    }
  }, [router, allowedRoles]);

  if (!authorized) {
    return (
        <div className="flex h-screen items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 dark:border-white"></div>
        </div>
    );
  }

  return <>{children}</>;
}
