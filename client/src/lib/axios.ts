import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor - attach access token
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Flag to prevent infinite refresh loops
let isRefreshing = false;
// Queue of callbacks waiting for the new token
let refreshSubscribers: ((token: string) => void)[] = [];

function onTokenRefreshed(token: string) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

function addRefreshSubscriber(cb: (token: string) => void) {
  refreshSubscribers.push(cb);
}

// Response interceptor — silently refresh on 401, then retry
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Only attempt refresh for 401s that haven't already been retried
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      typeof window !== 'undefined'
    ) {
      const refreshToken = localStorage.getItem('refresh_token');

      // No refresh token — go straight to login
      if (!refreshToken) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        redirectToLogin();
        return Promise.reject(error);
      }

      // If another request is already refreshing, queue this one
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          addRefreshSubscriber((newToken) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(api(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const res = await axios.post(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/auth/refresh`,
          { refresh_token: refreshToken }
        );

        const { access_token, refresh_token: newRefresh } = res.data;
        localStorage.setItem('access_token', access_token);
        if (newRefresh) localStorage.setItem('refresh_token', newRefresh);

        api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        onTokenRefreshed(access_token);

        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        return api(originalRequest);
      } catch {
        // Refresh failed — clear tokens and redirect
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        refreshSubscribers = [];
        redirectToLogin();
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

function redirectToLogin() {
  // If the student is mid-exam, don't hard-navigate away — the active page
  // handles its own reconnection UI. For all other routes, go to login.
  const path = window.location.pathname;
  const isActivePage = /\/student\/exam\/[^/]+\/active/.test(path);
  if (!isActivePage) {
    window.location.href = '/auth/login';
  }
}

export default api;
