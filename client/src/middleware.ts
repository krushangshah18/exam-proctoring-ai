import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const UNSUPPORTED_DEVICE_PATH = '/unsupported-device';

function isUnsupportedDevice(userAgent: string) {
  return /android|iphone|ipad|ipod|tablet|mobile|windows phone|kindle|silk|playbook/i.test(userAgent);
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/api') ||
    pathname === '/favicon.ico' ||
    pathname === UNSUPPORTED_DEVICE_PATH
  ) {
    return NextResponse.next();
  }

  const userAgent = request.headers.get('user-agent') ?? '';

  if (!userAgent || !isUnsupportedDevice(userAgent)) {
    return NextResponse.next();
  }

  const url = request.nextUrl.clone();
  const originalPath = `${pathname}${request.nextUrl.search}`;
  url.pathname = UNSUPPORTED_DEVICE_PATH;
  url.search = `?returnTo=${encodeURIComponent(originalPath)}`;
  return NextResponse.redirect(url);
}

export const config = {
  matcher: ['/((?!.*\\.[\\w]+$).*)'],
};
