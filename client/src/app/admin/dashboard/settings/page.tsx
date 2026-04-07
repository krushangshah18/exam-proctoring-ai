"use client";

import { useEffect, useMemo, useState } from "react";
import {
  CalendarClock,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  Save,
  ShieldCheck,
  User,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/axios";

interface Profile {
  full_name: string;
  email: string;
  role: string;
  last_login: string | null;
  created_at: string | null;
}

function Section({
  title,
  description,
  icon: Icon,
  children,
}: {
  title: string;
  description?: string;
  icon: LucideIcon;
  children: React.ReactNode;
}) {
  return (
    <div
      className="overflow-hidden rounded-2xl border bg-white"
      style={{
        borderColor: "#E2E8F0",
        boxShadow: "0 14px 40px rgba(15,23,42,0.05)",
      }}
    >
      <div
        className="flex items-start gap-3 px-5 py-4 sm:px-6"
        style={{ borderBottom: "1px solid #F1F5F9" }}
      >
        <div
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl"
          style={{ background: "#EFF6FF" }}
        >
          <Icon className="h-4.5 w-4.5" style={{ color: "#22577A" }} />
        </div>
        <div>
          <p className="text-sm font-semibold" style={{ color: "#0F172A" }}>
            {title}
          </p>
          {description && (
            <p className="mt-1 text-xs sm:text-sm" style={{ color: "#64748B" }}>
              {description}
            </p>
          )}
        </div>
      </div>
      <div className="p-5 sm:p-6">{children}</div>
    </div>
  );
}

function InfoField({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: React.ReactNode;
  icon: LucideIcon;
}) {
  return (
    <div
      className="rounded-2xl border p-4"
      style={{ borderColor: "#E2E8F0", background: "#FCFDFE" }}
    >
      <div className="mb-3 flex items-center gap-2">
        <div
          className="flex h-8 w-8 items-center justify-center rounded-lg"
          style={{ background: "#F8FAFC" }}
        >
          <Icon className="h-4 w-4" style={{ color: "#22577A" }} />
        </div>
        <p
          className="text-[11px] font-semibold uppercase tracking-[0.18em]"
          style={{ color: "#64748B" }}
        >
          {label}
        </p>
      </div>
      <div
        className="text-sm font-semibold break-words"
        style={{ color: "#0F172A" }}
      >
        {value}
      </div>
    </div>
  );
}

function formatDateTime(value: string | null, fallback = "Never") {
  if (!value) return fallback;
  return new Date(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export default function AdminSettingsPage() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [current, setCurrent] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [savingPw, setSavingPw] = useState(false);

  useEffect(() => {
    api
      .get("/auth/me")
      .then((r) => setProfile(r.data))
      .catch(() => toast.error("Failed to load profile"))
      .finally(() => setLoading(false));
  }, []);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPass.length < 8) {
      toast.error("Password must be at least 8 characters");
      return;
    }
    if (newPass !== confirm) {
      toast.error("Passwords do not match");
      return;
    }

    setSavingPw(true);
    try {
      await api.post("/auth/change-password", {
        current_password: current,
        new_password: newPass,
      });
      toast.success("Password updated successfully");
      setCurrent("");
      setNewPass("");
      setConfirm("");
    } catch (err: unknown) {
      const detail =
        typeof err === "object" &&
        err !== null &&
        "response" in err &&
        typeof err.response === "object" &&
        err.response !== null &&
        "data" in err.response &&
        typeof err.response.data === "object" &&
        err.response.data !== null &&
        "detail" in err.response.data
          ? err.response.data.detail
          : null;

      toast.error(
        typeof detail === "string" ? detail : "Failed to change password",
      );
    } finally {
      setSavingPw(false);
    }
  };

  const passwordChecks = useMemo(() => {
    const hasLength = newPass.length >= 8;
    const hasUpperLower = /[a-z]/.test(newPass) && /[A-Z]/.test(newPass);
    const hasNumber = /\d/.test(newPass);
    const matches = newPass.length > 0 && newPass === confirm;

    const score = [hasLength, hasUpperLower, hasNumber, matches].filter(
      Boolean,
    ).length;

    return {
      hasLength,
      hasUpperLower,
      hasNumber,
      matches,
      score,
      label:
        score >= 4
          ? "Strong password"
          : score >= 3
            ? "Good progress"
            : score >= 2
              ? "Needs improvement"
              : "Too weak",
      color:
        score >= 4
          ? "#15803D"
          : score >= 3
            ? "#0369A1"
            : score >= 2
              ? "#B45309"
              : "#DC2626",
      bg:
        score >= 4
          ? "#ECFDF5"
          : score >= 3
            ? "#F0F9FF"
            : score >= 2
              ? "#FFFBEB"
              : "#FEF2F2",
      progress: `${Math.max(score, 1) * 25}%`,
    };
  }, [newPass, confirm]);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-24">
        <Loader2
          className="h-7 w-7 animate-spin"
          style={{ color: "#CBD5E1" }}
        />
      </div>
    );
  }

  const inputBase =
    "w-full rounded-xl border px-3.5 py-3 text-sm outline-none transition-all";
  const passwordReady =
    !!current && !!newPass && newPass === confirm && newPass.length >= 8;

  return (
    <div className="max-w-6xl space-y-6 pb-12">
      <div
        className="relative overflow-hidden rounded-3xl px-6 py-7 text-white sm:px-8"
        style={{
          background:
            "linear-gradient(135deg, #22577A 0%, #2C7DA0 48%, #57CC99 100%)",
        }}
      >
        <div className="relative z-10 flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <p
              className="inline-flex items-center rounded-full px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em]"
              style={{
                background: "rgba(255,255,255,0.14)",
                color: "rgba(255,255,255,0.86)",
              }}
            >
              Account Settings
            </p>
            <h1
              className="mt-4 text-3xl font-bold leading-tight"
              style={{ letterSpacing: "-0.03em" }}
            >
              Keep your admin account secure and easy to manage.
            </h1>
            <p
              className="mt-3 max-w-xl text-sm sm:text-base"
              style={{ color: "rgba(255,255,255,0.78)" }}
            >
              Review your profile details, confirm account activity, and update
              your password from one place.
            </p>
          </div>

          <div
            className="grid gap-3 rounded-2xl border p-4 sm:grid-cols-2"
            style={{
              background: "rgba(15,23,42,0.14)",
              borderColor: "rgba(255,255,255,0.14)",
              backdropFilter: "blur(10px)",
            }}
          >
            <div>
              <p
                className="text-[11px] font-semibold uppercase tracking-[0.18em]"
                style={{ color: "rgba(255,255,255,0.62)" }}
              >
                Role
              </p>
              <p className="mt-1 text-sm font-semibold text-white">
                {profile?.role ?? "ADMIN"}
              </p>
            </div>
            <div>
              <p
                className="text-[11px] font-semibold uppercase tracking-[0.18em]"
                style={{ color: "rgba(255,255,255,0.62)" }}
              >
                Last Login
              </p>
              <p className="mt-1 text-sm font-semibold text-white">
                {formatDateTime(profile?.last_login ?? null)}
              </p>
            </div>
          </div>
        </div>

        <div
          className="absolute -right-12 -top-10 h-40 w-40 rounded-full"
          style={{ background: "rgba(255,255,255,0.09)" }}
        />
        <div
          className="absolute right-24 bottom-[-48px] h-28 w-28 rounded-full"
          style={{ background: "rgba(255,255,255,0.08)" }}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-12 xl:items-start">
        <div className="space-y-6 xl:col-span-5">
          <Section
            title="Account Overview"
            description="Identity and account status details used across the exam administration workspace."
            icon={User}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <InfoField
                label="Full Name"
                value={profile?.full_name ?? "—"}
                icon={User}
              />
              <InfoField
                label="Email Address"
                value={profile?.email ?? "—"}
                icon={Mail}
              />
              <InfoField
                label="Access Role"
                value={
                  <span className="inline-flex items-center gap-2">
                    <ShieldCheck
                      className="h-4 w-4"
                      style={{ color: "#22577A" }}
                    />
                    {profile?.role ?? "—"}
                  </span>
                }
                icon={ShieldCheck}
              />
              <InfoField
                label="Joined Platform"
                value={formatDateTime(
                  profile?.created_at ?? null,
                  "Unavailable",
                )}
                icon={CalendarClock}
              />
            </div>
          </Section>
        </div>

        <div className="space-y-6 xl:col-span-7">
          <Section
            title="Change Password"
            description="Use a strong password so access to exams, reports, and student data stays protected."
            icon={Lock}
          >
            <form onSubmit={handleChangePassword} className="space-y-5">
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label
                    className="mb-1.5 block text-sm font-medium"
                    style={{ color: "#475569" }}
                  >
                    Current Password
                  </label>
                  <div className="relative">
                    <input
                      type={showCurrent ? "text" : "password"}
                      value={current}
                      onChange={(e) => setCurrent(e.target.value)}
                      placeholder="Enter current password"
                      required
                      className={inputBase}
                      style={{
                        borderColor: "#E2E8F0",
                        color: "#0F172A",
                        paddingRight: "2.75rem",
                      }}
                      onFocus={(e) => {
                        (e.target as HTMLElement).style.borderColor = "#38A3A5";
                        (e.target as HTMLElement).style.boxShadow =
                          "0 0 0 4px rgba(56,163,165,0.12)";
                      }}
                      onBlur={(e) => {
                        (e.target as HTMLElement).style.borderColor = "#E2E8F0";
                        (e.target as HTMLElement).style.boxShadow = "none";
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowCurrent((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                      style={{ color: "#64748B" }}
                    >
                      {showCurrent ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                <div>
                  <label
                    className="mb-1.5 block text-sm font-medium"
                    style={{ color: "#475569" }}
                  >
                    New Password
                  </label>
                  <div className="relative">
                    <input
                      type={showNew ? "text" : "password"}
                      value={newPass}
                      onChange={(e) => setNewPass(e.target.value)}
                      placeholder="Create a stronger password"
                      required
                      minLength={8}
                      className={inputBase}
                      style={{
                        borderColor: "#E2E8F0",
                        color: "#0F172A",
                        paddingRight: "2.75rem",
                      }}
                      onFocus={(e) => {
                        (e.target as HTMLElement).style.borderColor = "#38A3A5";
                        (e.target as HTMLElement).style.boxShadow =
                          "0 0 0 4px rgba(56,163,165,0.12)";
                      }}
                      onBlur={(e) => {
                        (e.target as HTMLElement).style.borderColor = "#E2E8F0";
                        (e.target as HTMLElement).style.boxShadow = "none";
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setShowNew((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                      style={{ color: "#64748B" }}
                    >
                      {showNew ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              <div>
                <label
                  className="mb-1.5 block text-sm font-medium"
                  style={{ color: "#475569" }}
                >
                  Confirm New Password
                </label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder="Re-enter the new password"
                  required
                  className={inputBase}
                  style={{
                    borderColor:
                      confirm && confirm !== newPass ? "#EF4444" : "#E2E8F0",
                    color: "#0F172A",
                    boxShadow:
                      confirm && confirm !== newPass
                        ? "0 0 0 4px rgba(239,68,68,0.10)"
                        : "none",
                  }}
                  onFocus={(e) => {
                    if (!confirm || confirm === newPass) {
                      (e.target as HTMLElement).style.borderColor = "#38A3A5";
                      (e.target as HTMLElement).style.boxShadow =
                        "0 0 0 4px rgba(56,163,165,0.12)";
                    }
                  }}
                  onBlur={(e) => {
                    if (!confirm || confirm === newPass) {
                      (e.target as HTMLElement).style.borderColor = "#E2E8F0";
                      (e.target as HTMLElement).style.boxShadow = "none";
                    }
                  }}
                />
                {confirm && confirm !== newPass && (
                  <p className="mt-1.5 text-xs" style={{ color: "#EF4444" }}>
                    Passwords do not match.
                  </p>
                )}
              </div>

              <div
                className="rounded-2xl border p-4 sm:p-5"
                style={{ borderColor: "#E2E8F0", background: "#F8FAFC" }}
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p
                      className="text-sm font-semibold"
                      style={{ color: "#0F172A" }}
                    >
                      Password quality
                    </p>
                    <p className="mt-1 text-sm" style={{ color: "#64748B" }}>
                      {newPass
                        ? passwordChecks.label
                        : "Start typing to see live password guidance."}
                    </p>
                  </div>
                  <div
                    className="inline-flex items-center gap-2 self-start rounded-full px-3 py-1 text-xs font-semibold"
                    style={{
                      background: passwordChecks.bg,
                      color: passwordChecks.color,
                    }}
                  >
                    <KeyRound className="h-3.5 w-3.5" />
                    {newPass ? passwordChecks.label : "No password entered"}
                  </div>
                </div>

                <div
                  className="mt-4 h-2 overflow-hidden rounded-full"
                  style={{ background: "#E2E8F0" }}
                >
                  <div
                    className="h-full rounded-full transition-all duration-200"
                    style={{
                      width: newPass ? passwordChecks.progress : "8%",
                      background: passwordChecks.color,
                    }}
                  />
                </div>

                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  {[
                    {
                      ok: passwordChecks.hasLength,
                      label: "At least 8 characters",
                    },
                    {
                      ok: passwordChecks.hasUpperLower,
                      label: "Includes uppercase and lowercase letters",
                    },
                    {
                      ok: passwordChecks.hasNumber,
                      label: "Contains at least one number",
                    },
                    {
                      ok: passwordChecks.matches,
                      label: "Confirmation matches the new password",
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="flex items-center gap-2 rounded-xl border px-3 py-2.5"
                      style={{
                        borderColor: item.ok ? "#BBF7D0" : "#E2E8F0",
                        background: item.ok ? "#F0FDF4" : "#FFFFFF",
                      }}
                    >
                      <CheckCircle2
                        className="h-4 w-4 shrink-0"
                        style={{ color: item.ok ? "#16A34A" : "#CBD5E1" }}
                      />
                      <span
                        className="text-sm"
                        style={{ color: item.ok ? "#166534" : "#64748B" }}
                      >
                        {item.label}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-sm leading-6" style={{ color: "#64748B" }}>
                  Save only when the new password is complete and confirmed.
                  Your current session will remain active.
                </p>
                <button
                  type="submit"
                  disabled={savingPw || !passwordReady}
                  className="inline-flex items-center justify-center gap-2 rounded-xl px-5 py-3 text-sm font-semibold text-white transition-all duration-150"
                  style={{
                    background:
                      savingPw || !passwordReady ? "#64748B" : "#22577A",
                    cursor:
                      savingPw || !passwordReady ? "not-allowed" : "pointer",
                    boxShadow:
                      savingPw || !passwordReady
                        ? "none"
                        : "0 12px 28px rgba(34,87,122,0.22)",
                  }}
                >
                  {savingPw ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Save className="h-4 w-4" />
                  )}
                  Update Password
                </button>
              </div>
            </form>
          </Section>
        </div>
      </div>
    </div>
  );
}
