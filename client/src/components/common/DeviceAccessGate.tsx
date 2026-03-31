'use client';

import { useEffect } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';

const UNSUPPORTED_DEVICE_PATH = '/unsupported-device';

function isUnsupportedDevice() {
  const userAgent = navigator.userAgent || '';
  const isMobileOrTabletUa = /android|iphone|ipad|ipod|tablet|mobile|windows phone|kindle|silk|playbook/i.test(userAgent);
  const hasCoarsePointer =
    window.matchMedia('(pointer: coarse)').matches ||
    window.matchMedia('(any-pointer: coarse)').matches;
  const isTouchDevice = navigator.maxTouchPoints > 0 || hasCoarsePointer;
  const looksLikeDesktopNow = window.innerWidth >= 1024 && !hasCoarsePointer;
  const isSmallTouchViewport = window.innerWidth < 1024 && isTouchDevice;

  if (looksLikeDesktopNow) {
    return false;
  }

  return isMobileOrTabletUa || isSmallTouchViewport;
}

export function DeviceAccessGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  useEffect(() => {
    const syncRouteWithDevice = () => {
      const unsupported = isUnsupportedDevice();
      const currentQuery = searchParams.toString();
      const currentPath = currentQuery ? `${pathname}?${currentQuery}` : pathname;

      if (unsupported && pathname !== UNSUPPORTED_DEVICE_PATH) {
        router.replace(`${UNSUPPORTED_DEVICE_PATH}?returnTo=${encodeURIComponent(currentPath)}`);
        return;
      }

      if (!unsupported && pathname === UNSUPPORTED_DEVICE_PATH) {
        const returnTo = searchParams.get('returnTo');
        router.replace(returnTo && returnTo !== UNSUPPORTED_DEVICE_PATH ? returnTo : '/');
      }
    };

    syncRouteWithDevice();
    window.addEventListener('resize', syncRouteWithDevice);
    window.addEventListener('orientationchange', syncRouteWithDevice);

    return () => {
      window.removeEventListener('resize', syncRouteWithDevice);
      window.removeEventListener('orientationchange', syncRouteWithDevice);
    };
  }, [pathname, router, searchParams]);

  return <>{children}</>;
}
