'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Search, Users, Lock, Unlock, RefreshCw, Loader2,
  ShieldCheck, GraduationCap, ChevronLeft, ChevronRight,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel,
  AlertDialogContent, AlertDialogDescription,
  AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { toast } from 'sonner';
import api from '@/lib/axios';

// ── Types ─────────────────────────────────────────────────────────────────────

interface UserRow {
  id: string;
  full_name: string;
  email: string;
  role: string;
  is_active: boolean;
  is_locked: boolean;
  locked_until: string | null;
  failed_login_attempts: number;
  unlock_requests: number;
  last_login: string | null;
  created_at: string | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  const map: Record<string, { label: string; cls: string; Icon: any }> = {
    SYSADMIN: { label: 'SysAdmin', cls: 'bg-purple-100 text-purple-700 border-purple-200', Icon: ShieldCheck },
    ADMIN:    { label: 'Teacher',  cls: 'bg-blue-100 text-blue-700 border-blue-200',       Icon: ShieldCheck },
    STUDENT:  { label: 'Student',  cls: 'bg-slate-100 text-slate-600 border-slate-200',    Icon: GraduationCap },
  };
  const { label, cls, Icon } = map[role] ?? { label: role, cls: 'bg-slate-100 text-slate-600 border-slate-200', Icon: Users };
  return (
    <Badge variant="outline" className={`text-xs gap-1 ${cls}`}>
      <Icon className="h-3 w-3" />{label}
    </Badge>
  );
}

function fmtDate(iso: string | null) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: 'medium' });
}

function fmtDateTime(iso: string | null) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
}

const PAGE_SIZE = 25;

// ── Page ─────────────────────────────────────────────────────────────────────

export default function UsersPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState('all');
  const [lockFilter, setLockFilter] = useState('all');
  const [unlocking, setUnlocking] = useState<string | null>(null);
  const [confirmUnlock, setConfirmUnlock] = useState<UserRow | null>(null);
  const searchTimer = useRef<NodeJS.Timeout | null>(null);

  const fetchUsers = useCallback(async (p = page, q = search, role = roleFilter, lock = lockFilter) => {
    setLoading(true);
    try {
      const params: Record<string, any> = { page: p, limit: PAGE_SIZE };
      if (q.trim()) params.q = q.trim();
      if (role !== 'all') params.role = role;
      if (lock === 'locked') params.locked = true;
      if (lock === 'unlocked') params.locked = false;
      const res = await api.get('/admin/users', { params });
      setUsers(res.data.users);
      setTotal(res.data.total);
    } catch {
      toast.error('Failed to load users');
    } finally {
      setLoading(false);
    }
  }, [page, search, roleFilter, lockFilter]);

  useEffect(() => {
    fetchUsers(1, search, roleFilter, lockFilter);
    setPage(1);
  }, [roleFilter, lockFilter]);

  useEffect(() => {
    fetchUsers(page, search, roleFilter, lockFilter);
  }, [page]);

  const handleSearchChange = (v: string) => {
    setSearch(v);
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      setPage(1);
      fetchUsers(1, v, roleFilter, lockFilter);
    }, 400);
  };

  const handleUnlock = async (user: UserRow) => {
    setUnlocking(user.id);
    try {
      await api.post(`/admin-applications/users/unlock/${user.id}`);
      toast.success(`${user.full_name} unlocked`);
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, is_locked: false, failed_login_attempts: 0, locked_until: null } : u));
    } catch {
      toast.error('Failed to unlock user');
    } finally {
      setUnlocking(null);
      setConfirmUnlock(null);
    }
  };

  const lockedCount = users.filter(u => u.is_locked).length;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <>
      <div className="space-y-6 pb-12">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Users</h1>
            <p className="text-sm text-slate-500 mt-0.5">
              {total} user{total !== 1 ? 's' : ''} registered
              {lockedCount > 0 && <span className="ml-2 text-rose-500">· {lockedCount} locked on this page</span>}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => fetchUsers(page)} className="gap-2 border-slate-200">
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <Input
              placeholder="Search by name or email…"
              value={search}
              onChange={e => handleSearchChange(e.target.value)}
              className="pl-9 border-slate-200"
            />
          </div>
          <Select value={roleFilter} onValueChange={setRoleFilter}>
            <SelectTrigger className="w-40 border-slate-200">
              <SelectValue placeholder="Role" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Roles</SelectItem>
              <SelectItem value="STUDENT">Students</SelectItem>
              <SelectItem value="ADMIN">Teachers</SelectItem>
              <SelectItem value="SYSADMIN">SysAdmins</SelectItem>
            </SelectContent>
          </Select>
          <Select value={lockFilter} onValueChange={setLockFilter}>
            <SelectTrigger className="w-40 border-slate-200">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="locked">Locked</SelectItem>
              <SelectItem value="unlocked">Not Locked</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Table */}
        <Card className="border-slate-200 shadow-none overflow-hidden">
          {loading ? (
            <CardContent className="py-20 text-center">
              <Loader2 className="h-8 w-8 animate-spin text-slate-300 mx-auto" />
            </CardContent>
          ) : users.length === 0 ? (
            <CardContent className="py-20 text-center">
              <Users className="h-12 w-12 text-slate-200 mx-auto mb-3" />
              <p className="text-slate-400">No users found</p>
            </CardContent>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50">
                    {['Name / Email', 'Role', 'Status', 'Login Attempts', 'Last Login', 'Joined', ''].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {users.map(u => (
                    <tr key={u.id} className={`hover:bg-slate-50/50 transition-colors ${u.is_locked ? 'bg-rose-50/30' : ''}`}>
                      <td className="px-4 py-3">
                        <p className="font-medium text-slate-900">{u.full_name}</p>
                        <p className="text-xs text-slate-400">{u.email}</p>
                      </td>
                      <td className="px-4 py-3"><RoleBadge role={u.role} /></td>
                      <td className="px-4 py-3">
                        {u.is_locked ? (
                          <div>
                            <Badge variant="outline" className="text-xs bg-rose-50 text-rose-600 border-rose-200 gap-1">
                              <Lock className="h-3 w-3" /> Locked
                            </Badge>
                            {u.locked_until && (
                              <p className="text-xs text-slate-400 mt-0.5">Until {fmtDateTime(u.locked_until)}</p>
                            )}
                          </div>
                        ) : (
                          <Badge variant="outline" className="text-xs bg-emerald-50 text-emerald-600 border-emerald-200">Active</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {u.failed_login_attempts > 0 ? (
                          <span className="text-rose-500 font-semibold">{u.failed_login_attempts}</span>
                        ) : (
                          <span className="text-slate-400">0</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-slate-500 text-xs">{fmtDateTime(u.last_login)}</td>
                      <td className="px-4 py-3 text-slate-400 text-xs">{fmtDate(u.created_at)}</td>
                      <td className="px-4 py-3 text-right">
                        {u.is_locked && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs gap-1.5 border-rose-200 text-rose-600 hover:bg-rose-50"
                            disabled={unlocking === u.id}
                            onClick={() => setConfirmUnlock(u)}
                          >
                            {unlocking === u.id
                              ? <Loader2 className="h-3 w-3 animate-spin" />
                              : <Unlock className="h-3 w-3" />}
                            Unlock
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between text-sm text-slate-500">
            <span>Page {page} of {totalPages} · {total} users</span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="gap-1">
                <ChevronLeft className="h-4 w-4" /> Prev
              </Button>
              <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)} className="gap-1">
                Next <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Unlock confirmation */}
      <AlertDialog open={!!confirmUnlock} onOpenChange={open => { if (!open) setConfirmUnlock(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unlock Account</AlertDialogTitle>
            <AlertDialogDescription>
              This will reset the failed login counter and allow <strong>{confirmUnlock?.full_name}</strong> ({confirmUnlock?.email}) to log in again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-blue-600 hover:bg-blue-700"
              onClick={() => confirmUnlock && handleUnlock(confirmUnlock)}
            >
              Unlock Account
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
