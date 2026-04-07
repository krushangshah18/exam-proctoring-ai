"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import {
  Search,
  Users,
  Lock,
  Unlock,
  RefreshCw,
  Loader2,
  ShieldCheck,
  GraduationCap,
} from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { toast } from "sonner";
import api from "@/lib/axios";
import { TablePagination } from "@/components/common/TablePagination";

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
  const map: Record<
    string,
    { label: string; bg: string; color: string; border: string }
  > = {
    SYSADMIN: {
      label: "SysAdmin",
      bg: "#F5F3FF",
      color: "#7C3AED",
      border: "#DDD6FE",
    },
    ADMIN: {
      label: "Teacher",
      bg: "#EFF6FF",
      color: "#22577A",
      border: "#BFDBFE",
    },
    STUDENT: {
      label: "Student",
      bg: "#F8FAFC",
      color: "#475569",
      border: "#E2E8F0",
    },
  };
  const s = map[role] ?? {
    label: role,
    bg: "#F8FAFC",
    color: "#475569",
    border: "#E2E8F0",
  };
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-semibold border"
      style={{ background: s.bg, color: s.color, borderColor: s.border }}
    >
      {role === "SYSADMIN" ? (
        <ShieldCheck className="h-3 w-3" />
      ) : role === "STUDENT" ? (
        <GraduationCap className="h-3 w-3" />
      ) : (
        <ShieldCheck className="h-3 w-3" />
      )}
      {s.label}
    </span>
  );
}

function fmtDate(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, { dateStyle: "medium" });
}
function fmtDateTime(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "short",
    timeStyle: "short",
  });
}
function fmtShortDate(iso: string | null) {
  if (!iso) return "—";
  const date = new Date(iso);
  const day = String(date.getDate()).padStart(2, "0");
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const year = String(date.getFullYear()).slice(-2);
  return `${day}/${month}/${year}`;
}

const PAGE_SIZE = 25;

// ── Page ─────────────────────────────────────────────────────────────────────
export default function UsersPage() {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");
  const [lockFilter, setLockFilter] = useState("all");
  const [unlocking, setUnlocking] = useState<string | null>(null);
  const [confirmUnlock, setConfirmUnlock] = useState<UserRow | null>(null);
  const searchTimer = useRef<NodeJS.Timeout | null>(null);

  const fetchUsers = useCallback(
    async (p = page, q = search, role = roleFilter, lock = lockFilter) => {
      setLoading(true);
      try {
        const params: Record<string, any> = { page: p, limit: PAGE_SIZE };
        if (q.trim()) params.q = q.trim();
        if (role !== "all") params.role = role;
        if (lock === "locked") params.locked = true;
        if (lock === "unlocked") params.locked = false;
        const res = await api.get("/admin/users", { params });
        setUsers(res.data.users);
        setTotal(res.data.total);
      } catch {
        toast.error("Failed to load users");
      } finally {
        setLoading(false);
      }
    },
    [page, search, roleFilter, lockFilter],
  );

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
      setUsers((prev) =>
        prev.map((u) =>
          u.id === user.id
            ? {
                ...u,
                is_locked: false,
                failed_login_attempts: 0,
                locked_until: null,
              }
            : u,
        ),
      );
    } catch {
      toast.error("Failed to unlock user");
    } finally {
      setUnlocking(null);
      setConfirmUnlock(null);
    }
  };

  const lockedCount = users.filter((u) => u.is_locked).length;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  const ROLES = [
    { v: "all", l: "All Roles" },
    { v: "STUDENT", l: "Students" },
    { v: "ADMIN", l: "Teachers" },
    { v: "SYSADMIN", l: "SysAdmins" },
  ];
  const LOCKS = [
    { v: "all", l: "All Status" },
    { v: "locked", l: "Locked" },
    { v: "unlocked", l: "Active" },
  ];

  return (
    <>
      <div className="space-y-6 max-w-6xl pb-12">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1
              className="text-2xl font-bold"
              style={{ color: "#0F172A", letterSpacing: "-0.025em" }}
            >
              Users
            </h1>
            <p
              className="text-sm mt-1 font-medium"
              style={{ color: "#64748B" }}
            >
              {total} user{total !== 1 ? "s" : ""} registered
              {lockedCount > 0 && (
                <span
                  className="ml-2 font-semibold"
                  style={{ color: "#E11D48" }}
                >
                  · {lockedCount} locked on this page
                </span>
              )}
            </p>
          </div>
          <button
            onClick={() => fetchUsers(page)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
            style={{
              borderColor: "#E2E8F0",
              color: "#475569",
              background: "#fff",
            }}
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4"
              style={{ color: "#64748B" }}
            />
            <input
              type="text"
              placeholder="Search by name or email…"
              value={search}
              onChange={(e) => handleSearchChange(e.target.value)}
              className="w-full pl-9 pr-4 py-2.5 text-sm rounded-lg border outline-none transition-all"
              style={{
                borderColor: "#E2E8F0",
                color: "#0F172A",
                background: "#fff",
              }}
              onFocus={(e) => {
                (e.target as HTMLElement).style.borderColor = "#38A3A5";
                (e.target as HTMLElement).style.boxShadow =
                  "0 0 0 3px rgba(56,163,165,0.12)";
              }}
              onBlur={(e) => {
                (e.target as HTMLElement).style.borderColor = "#E2E8F0";
                (e.target as HTMLElement).style.boxShadow = "none";
              }}
            />
          </div>
          {[
            { val: roleFilter, set: setRoleFilter, opts: ROLES },
            { val: lockFilter, set: setLockFilter, opts: LOCKS },
          ].map((s, i) => (
            <select
              key={i}
              value={s.val}
              onChange={(e) => s.set(e.target.value)}
              className="w-40 px-3 py-2.5 text-sm rounded-lg border outline-none cursor-pointer"
              style={{
                borderColor: "#E2E8F0",
                color: "#475569",
                background: "#fff",
              }}
            >
              {s.opts.map((o) => (
                <option key={o.v} value={o.v}>
                  {o.l}
                </option>
              ))}
            </select>
          ))}
        </div>

        {/* Table */}
        <div
          className="bg-white rounded-xl border overflow-hidden"
          style={{
            borderColor: "#E2E8F0",
            boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
          }}
        >
          {loading ? (
            <div className="py-20 flex justify-center">
              <Loader2
                className="h-7 w-7 animate-spin"
                style={{ color: "#64748B" }}
              />
            </div>
          ) : users.length === 0 ? (
            <div className="py-20 text-center">
              <Users
                className="h-10 w-10 mx-auto mb-3"
                style={{ color: "#E2E8F0" }}
              />
              <p className="text-sm font-medium" style={{ color: "#64748B" }}>
                No users found
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr
                    style={{
                      borderBottom: "1px solid #F1F5F9",
                      background: "#F8FAFC",
                    }}
                  >
                    {[
                      "Name / Email",
                      "Role",
                      "Status",
                      "Failed Login Attempts",
                      "Last Login",
                      "Joined",
                      "",
                    ].map((h) => (
                      <th
                        key={h}
                        className={`px-4 py-3 text-[11px] font-semibold uppercase tracking-wider ${h === "Failed Login Attempts" ? "text-center" : "text-left"}`}
                        style={{ color: "#64748B" }}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map((u, idx) => (
                    <tr
                      key={u.id}
                      style={{
                        borderBottom:
                          idx < users.length - 1 ? "1px solid #F8FAFC" : "none",
                        background: u.is_locked
                          ? "rgba(239,68,68,0.02)"
                          : "transparent",
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLElement).style.background =
                          "#F8FAFC";
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.background =
                          u.is_locked ? "rgba(239,68,68,0.02)" : "transparent";
                      }}
                    >
                      <td className="px-4 py-3">
                        <p
                          className="font-semibold"
                          style={{ color: "#0F172A" }}
                        >
                          {u.full_name}
                        </p>
                        <p
                          className="text-xs mt-0.5 font-medium"
                          style={{ color: "#64748B" }}
                        >
                          {u.email}
                        </p>
                      </td>
                      <td className="px-4 py-3">
                        <RoleBadge role={u.role} />
                      </td>
                      <td className="px-4 py-3">
                        {u.is_locked ? (
                          <div>
                            <span
                              className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-semibold border"
                              style={{
                                background: "#FFF1F2",
                                color: "#BE123C",
                                borderColor: "#FECDD3",
                              }}
                            >
                              <Lock className="h-3 w-3" /> Locked
                            </span>
                            {u.locked_until && (
                              <p
                                className="text-xs mt-0.5 font-medium"
                                style={{ color: "#64748B" }}
                              >
                                Until {fmtDateTime(u.locked_until)}
                              </p>
                            )}
                          </div>
                        ) : (
                          <span
                            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-semibold border"
                            style={{
                              background: "#ECFDF5",
                              color: "#15803D",
                              borderColor: "#BBF7D0",
                            }}
                          >
                            Active
                          </span>
                        )}
                      </td>
                      <td
                        className="px-4 py-3 text-center tabular-nums font-semibold"
                        style={{
                          color:
                            u.failed_login_attempts > 0 ? "#DC2626" : "#64748B",
                        }}
                      >
                        {u.failed_login_attempts}
                      </td>
                      <td
                        className="px-4 py-3 text-xs"
                        style={{ color: "#475569" }}
                      >
                        {fmtShortDate(u.last_login)}
                      </td>
                      <td
                        className="px-4 py-3 text-xs font-medium"
                        style={{ color: "#64748B" }}
                      >
                        {fmtDate(u.created_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {u.is_locked && (
                          <button
                            disabled={unlocking === u.id}
                            onClick={() => setConfirmUnlock(u)}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150"
                            style={{
                              background: "#FFF1F2",
                              color: "#BE123C",
                              borderColor: "#FECDD3",
                            }}
                            onMouseEnter={(e) => {
                              (
                                e.currentTarget as HTMLElement
                              ).style.background = "#FFE4E6";
                            }}
                            onMouseLeave={(e) => {
                              (
                                e.currentTarget as HTMLElement
                              ).style.background = "#FFF1F2";
                            }}
                          >
                            {unlocking === u.id ? (
                              <Loader2 className="h-3 w-3 animate-spin" />
                            ) : (
                              <Unlock className="h-3 w-3" />
                            )}
                            Unlock
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Pagination */}
        {total > 10 && (
          <TablePagination
            page={page}
            pageCount={totalPages}
            pageSize={PAGE_SIZE}
            totalItems={total}
            onPageChange={setPage}
          />
        )}
      </div>

      {/* Unlock dialog */}
      <AlertDialog
        open={!!confirmUnlock}
        onOpenChange={(open) => {
          if (!open) setConfirmUnlock(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Unlock Account</AlertDialogTitle>
            <AlertDialogDescription>
              This will reset the failed login counter and allow{" "}
              <strong>{confirmUnlock?.full_name}</strong> (
              {confirmUnlock?.email}) to log in again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              style={{ background: "#22577A" }}
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
