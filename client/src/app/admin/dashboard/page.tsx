"use client";

import { useState, useEffect } from "react";
import {
  PlusCircle,
  Users,
  ClipboardCheck,
  Activity,
  ArrowRight,
  FileText,
  Loader2,
  BookOpen,
  Siren,
  ArrowUpRight,
  Calendar,
  Clock,
} from "lucide-react";
import { useRouter } from "next/navigation";
import api from "@/lib/axios";

interface Stats {
  total_exams: number;
  live_exams: number;
  total_sessions: number;
  live_sessions: number;
  pending_appeals: number;
  total_students: number;
}

interface RecentExam {
  id: string;
  title: string;
  status: string;
  start_window: string | null;
  duration_minutes: number;
  invite_count: number;
}

const STATUS_STYLES: Record<
  string,
  { bg: string; color: string; border: string }
> = {
  LIVE: { bg: "#ECFDF5", color: "#15803D", border: "#BBF7D0" },
  SCHEDULED: { bg: "#EFF6FF", color: "#1D4ED8", border: "#BFDBFE" },
  ENDED: { bg: "#F8FAFC", color: "#475569", border: "#E2E8F0" },
  CANCELLED: { bg: "#FFF1F2", color: "#BE123C", border: "#FECDD3" },
  DRAFT: { bg: "#F8FAFC", color: "#64748B", border: "#E2E8F0" },
};

function fmtWindow(iso: string | null) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export default function AdminDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [recentExams, setRecentExams] = useState<RecentExam[]>([]);
  const [loadingStats, setLoadingStats] = useState(true);

  useEffect(() => {
    Promise.all([
      api.get("/auth/me"),
      api.get("/admin/exams/stats"),
      api.get("/admin/exams"),
    ])
      .then(([userRes, statsRes, examsRes]) => {
        setUser(userRes.data);
        setStats(statsRes.data);
        setRecentExams((examsRes.data as RecentExam[]).slice(0, 5));
      })
      .catch(() => {})
      .finally(() => setLoadingStats(false));
  }, []);

  const metrics = stats
    ? [
        {
          title: "Live Sessions",
          value: stats.live_sessions,
          icon: Activity,
          description: `${stats.total_sessions} total sessions`,
          iconBg: "#ECFDF5",
          iconColor: "#15803D",
          alert: stats.live_sessions > 0,
        },
        {
          title: "Active Exams",
          value: stats.live_exams,
          icon: BookOpen,
          description: `${stats.total_exams} total exams created`,
          iconBg: "#EFF6FF",
          iconColor: "#22577A",
          alert: false,
        },
        {
          title: "Total Students",
          value: stats.total_students,
          icon: Users,
          description: "Invited across all exams",
          iconBg: "#F5F3FF",
          iconColor: "#7C3AED",
          alert: false,
        },
        {
          title: "Pending Appeals",
          value: stats.pending_appeals,
          icon: ClipboardCheck,
          description: "Termination appeals awaiting review",
          iconBg: "#FFFBEB",
          iconColor: "#B45309",
          alert: stats.pending_appeals > 0,
        },
      ]
    : [];

  return (
    <div className="space-y-8 max-w-6xl">
      {/* Welcome banner */}
      <div
        className="rounded-2xl p-8 text-white relative overflow-hidden"
        style={{
          background: "linear-gradient(135deg, #22577A 0%, #38A3A5 100%)",
        }}
      >
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <h1
              className="text-3xl font-bold mb-2"
              style={{ letterSpacing: "-0.03em" }}
            >
              Welcome back, {user?.full_name?.split(" ")[0] || "Admin"}
            </h1>
            <p
              style={{
                color: "rgba(255,255,255,0.75)",
                maxWidth: "420px",
                fontSize: "0.9rem",
              }}
            >
              {stats?.pending_appeals
                ? `You have ${stats.pending_appeals} pending appeal${stats.pending_appeals !== 1 ? "s" : ""} awaiting review.`
                : stats?.live_sessions
                  ? `${stats.live_sessions} student${stats.live_sessions !== 1 ? "s" : ""} currently taking exams.`
                  : "Monitor your exams and review proctoring reports."}
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            {stats && stats.pending_appeals > 0 && (
              <button
                onClick={() => router.push("/admin/dashboard/appeals")}
                className="flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all duration-150"
                style={{ background: "#F59E0B", color: "#0F172A" }}
                onMouseEnter={(e) =>
                  ((e.currentTarget as HTMLElement).style.background =
                    "#D97706")
                }
                onMouseLeave={(e) =>
                  ((e.currentTarget as HTMLElement).style.background =
                    "#F59E0B")
                }
              >
                <Siren className="h-4 w-4" /> Review Appeals Now
              </button>
            )}
            <button
              onClick={() => router.push("/admin/dashboard/exams/new")}
              className="flex items-center gap-2 px-5 py-3 rounded-xl text-sm font-semibold transition-all duration-150"
              style={{
                background: "rgba(255,255,255,0.15)",
                color: "#fff",
                border: "1px solid rgba(255,255,255,0.25)",
              }}
              onMouseEnter={(e) =>
                ((e.currentTarget as HTMLElement).style.background =
                  "rgba(255,255,255,0.22)")
              }
              onMouseLeave={(e) =>
                ((e.currentTarget as HTMLElement).style.background =
                  "rgba(255,255,255,0.15)")
              }
            >
              <PlusCircle className="h-4 w-4" /> Create New Exam
            </button>
          </div>
        </div>
        {/* Decorative circles */}
        <div
          className="absolute -right-8 -top-8 h-40 w-40 rounded-full opacity-10"
          style={{ background: "#57CC99" }}
        />
        <div
          className="absolute right-20 -bottom-12 h-28 w-28 rounded-full opacity-10"
          style={{ background: "#fff" }}
        />
      </div>

      {/* Metrics Grid */}
      {loadingStats ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="bg-white rounded-xl border p-5 flex items-center justify-center h-24"
              style={{ borderColor: "#E2E8F0" }}
            >
              <Loader2
                className="h-5 w-5 animate-spin"
                style={{ color: "#CBD5E1" }}
              />
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {metrics.map((metric, i) => (
            <div
              key={i}
              className="bg-white rounded-xl border p-5 transition-shadow duration-150"
              style={{
                borderColor:
                  metric.alert && metric.title === "Pending Appeals"
                    ? "#FDE68A"
                    : "#E2E8F0",
                boxShadow:
                  metric.alert && metric.title === "Pending Appeals"
                    ? "0 0 0 3px rgba(245,158,11,0.12), 0 1px 3px rgba(15,23,42,0.04)"
                    : "0 1px 3px rgba(15,23,42,0.04)",
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <p
                  className="text-xs font-semibold uppercase tracking-wider"
                  style={{ color: "#64748B" }}
                >
                  {metric.title}
                </p>
                <div
                  className="p-1.5 rounded-lg relative"
                  style={{ background: metric.iconBg }}
                >
                  <metric.icon
                    className="h-4 w-4"
                    style={{ color: metric.iconColor }}
                  />
                  {metric.alert && (
                    <span
                      className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full border-2 border-white"
                      style={{ background: "#F59E0B" }}
                    />
                  )}
                </div>
              </div>
              <p
                className="text-3xl font-bold"
                style={{ color: "#0F172A", letterSpacing: "-0.03em" }}
              >
                {metric.value}
              </p>
              <p className="text-xs mt-1" style={{ color: "#64748B" }}>
                {metric.description}
              </p>
              {metric.title === "Pending Appeals" && metric.value > 0 && (
                <button
                  className="mt-3 text-xs font-semibold flex items-center gap-1 transition-colors"
                  style={{ color: "#B45309" }}
                  onClick={() => router.push("/admin/dashboard/appeals")}
                >
                  Open appeal inbox <ArrowRight className="h-3 w-3" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Recent Exams */}
      <div
        className="bg-white rounded-xl border overflow-hidden"
        style={{
          borderColor: "#E2E8F0",
          boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
        }}
      >
        <div
          className="flex items-center justify-between px-5 py-4"
          style={{ borderBottom: "1px solid #F1F5F9" }}
        >
          <div>
            <p className="text-sm font-semibold" style={{ color: "#0F172A" }}>
              Recent Exams
            </p>
            <p className="text-xs mt-0.5" style={{ color: "#64748B" }}>
              Your latest exams
            </p>
          </div>
          <button
            onClick={() => router.push("/admin/dashboard/exams")}
            className="flex items-center gap-1.5 text-xs font-semibold transition-colors"
            style={{ color: "#22577A" }}
          >
            View All <ArrowUpRight className="h-3.5 w-3.5" />
          </button>
        </div>
        {recentExams.length === 0 ? (
          <div
            className="py-12 text-center text-sm"
            style={{ color: "#64748B" }}
          >
            No exams yet
          </div>
        ) : (
          <div>
            {recentExams.map((exam, idx) => {
              const s = STATUS_STYLES[exam.status] ?? STATUS_STYLES.DRAFT;
              return (
                <div
                  key={exam.id}
                  className="flex items-center justify-between px-5 py-4 cursor-pointer transition-colors"
                  style={{
                    borderBottom:
                      idx < recentExams.length - 1
                        ? "1px solid #F8FAFC"
                        : "none",
                  }}
                  onMouseEnter={(e) =>
                    ((e.currentTarget as HTMLElement).style.background =
                      "#F8FAFC")
                  }
                  onMouseLeave={(e) =>
                    ((e.currentTarget as HTMLElement).style.background =
                      "transparent")
                  }
                  onClick={() =>
                    router.push(`/admin/dashboard/exams/${exam.id}`)
                  }
                >
                  <div className="flex items-center gap-4">
                    <div
                      className="h-10 w-10 rounded-lg flex items-center justify-center shrink-0"
                      style={{ background: "#EFF6FF" }}
                    >
                      <FileText
                        className="h-5 w-5"
                        style={{ color: "#22577A" }}
                      />
                    </div>
                    <div>
                      <p
                        className="font-semibold text-sm"
                        style={{ color: "#0F172A" }}
                      >
                        {exam.title}
                      </p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-semibold"
                          style={{ background: s.bg, color: s.color }}
                        >
                          {exam.status}
                        </span>
                        <span
                          className="text-xs flex items-center gap-1"
                          style={{ color: "#64748B" }}
                        >
                          <Users className="h-3 w-3" /> {exam.invite_count}
                          <Clock className="h-3 w-3 ml-1" />{" "}
                          {exam.duration_minutes}m
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <p
                      className="text-xs hidden md:block"
                      style={{ color: "#64748B" }}
                    >
                      <Calendar className="h-3 w-3 inline mr-1" />
                      {fmtWindow(exam.start_window)}
                    </p>
                    <span
                      className="text-xs font-semibold px-3 py-1.5 rounded-lg border"
                      style={{ borderColor: "#E2E8F0", color: "#475569" }}
                    >
                      Manage
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
