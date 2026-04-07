"use client";

import { useState, useEffect } from "react";
import RoleGuard from "@/components/auth/role-guard";
import DeviceManagement from "@/components/auth/device-management";
import {
  StudentPageShell,
  StudentStyles,
} from "@/components/student/StudentShell";
import {
  Calendar,
  Clock,
  ArrowRight,
  History,
  Loader2,
  BookOpen,
  AlertTriangle,
  GraduationCap,
} from "lucide-react";
import { useRouter } from "next/navigation";
import api from "@/lib/axios";
import { toast } from "sonner";
import { parseUTC, fmtTimeTZ } from "@/lib/fmt-date";

interface UpcomingExam {
  id: string;
  title: string;
  exam_mode: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  hard_join_deadline: string | null;
  status: string;
}

function ExamCard({
  exam,
  onClick,
}: {
  exam: UpcomingExam;
  onClick: () => void;
}) {
  const isLive = exam.status === "LIVE";
  const startDate = parseUTC(exam.start_window);
  const isToday = startDate.toDateString() === new Date().toDateString();
  const isTomorrow =
    startDate.toDateString() === new Date(Date.now() + 86400000).toDateString();

  const dateLabel = isToday
    ? "Today"
    : isTomorrow
      ? "Tomorrow"
      : startDate.toLocaleDateString(undefined, {
          month: "short",
          day: "numeric",
        });

  const [hovered, setHovered] = useState(false);

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: "#fff",
        border: `1.5px solid ${isLive ? "rgba(34,197,94,0.42)" : hovered ? "#38A3A5" : "#CBD5E1"}`,
        borderRadius: "12px",
        padding: "18px 20px",
        cursor: "pointer",
        transition: "border-color 150ms, box-shadow 150ms",
        boxShadow: hovered
          ? "0 10px 24px rgba(34,87,122,0.12)"
          : "0 6px 18px rgba(15,23,42,0.05)",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Live glow accent */}
      {isLive && (
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: "3px",
            background: "linear-gradient(90deg, #22C55E, #57CC99)",
          }}
        />
      )}

      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "12px",
          marginBottom: "12px",
        }}
      >
        <h3
          style={{
            fontWeight: 700,
            fontSize: "14.5px",
            color: hovered ? "#22577A" : "#0F172A",
            lineHeight: 1.4,
            transition: "color 150ms",
            display: "-webkit-box",
            WebkitLineClamp: 2,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
        >
          {exam.title}
        </h3>
        {isLive ? (
          <span className="st-badge st-badge-live" style={{ flexShrink: 0 }}>
            <span
              style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                background: "#16A34A",
                display: "inline-block",
                animation: "st-pulse-dot 1.5s ease-in-out infinite",
              }}
            />
            Live Now
          </span>
        ) : (
          <span
            className="st-badge st-badge-scheduled"
            style={{ flexShrink: 0 }}
          >
            Upcoming
          </span>
        )}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "7px",
            fontSize: "13px",
            color: "#64748B",
          }}
        >
          <Calendar
            style={{
              width: "13px",
              height: "13px",
              color: "#64748B",
              flexShrink: 0,
            }}
          />
          <span>
            <strong style={{ color: isToday ? "#16A34A" : "#475569" }}>
              {dateLabel}
            </strong>{" "}
            at {fmtTimeTZ(exam.start_window)}
          </span>
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "7px",
            fontSize: "13px",
            color: "#64748B",
          }}
        >
          <Clock
            style={{
              width: "13px",
              height: "13px",
              color: "#64748B",
              flexShrink: 0,
            }}
          />
          <span>{exam.duration_minutes} minutes</span>
        </div>
        {exam.hard_join_deadline && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "7px",
              fontSize: "13px",
              color: "#D97706",
            }}
          >
            <AlertTriangle
              style={{ width: "13px", height: "13px", flexShrink: 0 }}
            />
            <span>
              Deadline:{" "}
              {parseUTC(exam.hard_join_deadline).toLocaleDateString(undefined, {
                month: "short",
                day: "numeric",
              })}{" "}
              at {fmtTimeTZ(exam.hard_join_deadline)}
            </span>
          </div>
        )}
      </div>

      <div
        style={{
          marginTop: "14px",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <span
          style={{
            fontSize: "10.5px",
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.08em",
            color: "#64748B",
            background: "#F8FAFC",
            padding: "3px 8px",
            borderRadius: "4px",
            border: "1px solid #CBD5E1",
          }}
        >
          {exam.exam_mode}
        </span>
        <span
          style={{
            fontSize: "12px",
            fontWeight: 700,
            color: "#22577A",
            display: "flex",
            alignItems: "center",
            gap: "3px",
            opacity: hovered ? 1 : 0,
            transition: "opacity 150ms",
          }}
        >
          Open <ArrowRight style={{ width: "13px", height: "13px" }} />
        </span>
      </div>
    </div>
  );
}

function SectionHeader({
  icon,
  title,
  count,
}: {
  icon: React.ReactNode;
  title: string;
  count?: number;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        marginBottom: "16px",
      }}
    >
      <div
        style={{
          width: "32px",
          height: "32px",
          borderRadius: "8px",
          background: "rgba(34,87,122,0.08)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {icon}
      </div>
      <h2 style={{ fontSize: "15px", fontWeight: 700, color: "#0F172A" }}>
        {title}
      </h2>
      {count !== undefined && (
        <span
          style={{
            fontSize: "11px",
            fontWeight: 700,
            color: "#22577A",
            background: "rgba(34,87,122,0.08)",
            padding: "2px 8px",
            borderRadius: "10px",
          }}
        >
          {count}
        </span>
      )}
    </div>
  );
}

export default function StudentDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);
  const [exams, setExams] = useState<UpcomingExam[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [userRes, examsRes] = await Promise.all([
        api.get("/auth/me"),
        api.get("/exam/upcoming"),
      ]);
      setUser(userRes.data);
      setExams(examsRes.data);
    } catch {
      toast.error("Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      const refreshToken = localStorage.getItem("refresh_token");
      if (refreshToken)
        await api.post("/auth/logout", { refresh_token: refreshToken });
    } catch {
    } finally {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      toast.success("Logged out successfully");
      router.push("/auth/login");
    }
  };

  const liveExams = exams.filter((e) => e.status === "LIVE");
  const scheduledExams = exams.filter((e) => e.status === "SCHEDULED");

  return (
    <RoleGuard allowedRoles={["STUDENT"]}>
      <StudentPageShell user={user} onLogout={handleLogout} loading={loading}>
        {/* Welcome banner */}
        <div
          style={{
            background: "linear-gradient(135deg, #22577A 0%, #38A3A5 100%)",
            borderRadius: "14px",
            padding: "28px 32px",
            marginBottom: "28px",
            position: "relative",
            overflow: "hidden",
            boxShadow: "0 18px 40px rgba(34, 87, 122, 0.16)",
          }}
        >
          {/* Dot grid */}
          <div
            style={{
              position: "absolute",
              inset: 0,
              backgroundImage:
                "radial-gradient(rgba(255,255,255,0.08) 1px, transparent 1px)",
              backgroundSize: "22px 22px",
              pointerEvents: "none",
            }}
          />
          {/* Watermark */}
          <div
            style={{
              position: "absolute",
              right: "-20px",
              bottom: "-20px",
              opacity: 0.06,
              pointerEvents: "none",
            }}
          >
            <GraduationCap
              style={{ width: "140px", height: "140px", color: "#fff" }}
            />
          </div>

          <div style={{ position: "relative", zIndex: 1 }}>
            <p
              style={{
                fontSize: "12px",
                fontWeight: 700,
                color: "rgba(255,255,255,0.5)",
                letterSpacing: "0.12em",
                textTransform: "uppercase",
                marginBottom: "6px",
              }}
            >
              Student Dashboard
            </p>
            <h2
              style={{
                fontSize: "24px",
                fontWeight: 800,
                color: "#fff",
                letterSpacing: "-0.02em",
                marginBottom: "4px",
              }}
            >
              {loading
                ? "Loading…"
                : `Welcome back, ${user?.full_name?.split(" ")[0] || "Student"}!`}
            </h2>
            <p style={{ fontSize: "13.5px", color: "rgba(255,255,255,0.6)" }}>
              {loading
                ? ""
                : liveExams.length > 0
                  ? `You have ${liveExams.length} live exam${liveExams.length > 1 ? "s" : ""} right now.`
                  : scheduledExams.length > 0
                    ? `You have ${scheduledExams.length} upcoming exam${scheduledExams.length > 1 ? "s" : ""}.`
                    : "No upcoming exams at this time."}
            </p>

            <div
              style={{
                marginTop: "20px",
                display: "flex",
                gap: "8px",
                flexWrap: "wrap",
              }}
            >
              <button
                onClick={() => router.push("/student/history")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  padding: "8px 16px",
                  borderRadius: "8px",
                  cursor: "pointer",
                  background: "rgba(255,255,255,0.15)",
                  border: "1px solid rgba(255,255,255,0.25)",
                  color: "#fff",
                  fontSize: "13px",
                  fontWeight: 600,
                  fontFamily: "'Plus Jakarta Sans', sans-serif",
                  transition: "background 150ms",
                }}
                onMouseEnter={(e) =>
                  ((e.currentTarget as HTMLElement).style.background =
                    "rgba(255,255,255,0.25)")
                }
                onMouseLeave={(e) =>
                  ((e.currentTarget as HTMLElement).style.background =
                    "rgba(255,255,255,0.15)")
                }
              >
                <History style={{ width: "14px", height: "14px" }} />
                Exam History
              </button>
            </div>
          </div>
        </div>

        {/* Live Exams */}
        {!loading && liveExams.length > 0 && (
          <div style={{ marginBottom: "28px" }} className="st-fadein">
            <SectionHeader
              icon={
                <span
                  style={{
                    width: "12px",
                    height: "12px",
                    borderRadius: "50%",
                    background: "#22C55E",
                    display: "inline-block",
                  }}
                />
              }
              title="Live Now"
              count={liveExams.length}
            />
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fill, minmax(300px, 1fr))",
                gap: "14px",
              }}
            >
              {liveExams.map((exam) => (
                <ExamCard
                  key={exam.id}
                  exam={exam}
                  onClick={() => router.push(`/student/exam/${exam.id}/info`)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Upcoming Exams */}
        <div style={{ marginBottom: "28px" }} className="st-fadein">
          <div
            style={{
              background: "#fff",
              border: "1.5px solid #CBD5E1",
              borderRadius: "14px",
              overflow: "hidden",
              boxShadow: "0 12px 28px rgba(15,23,42,0.05)",
            }}
          >
            <div
              style={{
                padding: "18px 22px",
                borderBottom: "1px solid #E2E8F0",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <SectionHeader
                icon={
                  <Calendar
                    style={{ width: "15px", height: "15px", color: "#22577A" }}
                  />
                }
                title="Upcoming Exams"
              />
              {!loading && scheduledExams.length > 0 && (
                <span className="st-badge st-badge-muted">
                  {scheduledExams.length} scheduled
                </span>
              )}
            </div>

            <div style={{ padding: "20px 22px" }}>
              {loading ? (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "10px",
                    padding: "40px 0",
                    color: "#64748B",
                  }}
                >
                  <Loader2
                    style={{
                      width: "20px",
                      height: "20px",
                      animation: "spin 1s linear infinite",
                    }}
                  />
                  <span style={{ fontSize: "14px" }}>Loading exams…</span>
                  <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
                </div>
              ) : scheduledExams.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px 0" }}>
                  <BookOpen
                    style={{
                      width: "44px",
                      height: "44px",
                      color: "#E2E8F0",
                      margin: "0 auto 14px",
                    }}
                  />
                  <p
                    style={{
                      fontSize: "14px",
                      fontWeight: 600,
                      color: "#64748B",
                      marginBottom: "4px",
                    }}
                  >
                    No upcoming exams
                  </p>
                  <p style={{ fontSize: "13px", color: "#64748B" }}>
                    You'll be notified when a new exam is assigned to you.
                  </p>
                  <button
                    onClick={() => router.push("/student/history")}
                    className="st-btn-ghost"
                    style={{ marginTop: "16px", fontSize: "13px" }}
                  >
                    <History style={{ width: "14px", height: "14px" }} /> View
                    Exam History
                  </button>
                </div>
              ) : (
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns:
                      "repeat(auto-fill, minmax(300px, 1fr))",
                    gap: "14px",
                  }}
                >
                  {scheduledExams.map((exam) => (
                    <ExamCard
                      key={exam.id}
                      exam={exam}
                      onClick={() =>
                        router.push(`/student/exam/${exam.id}/info`)
                      }
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Device Management */}
        <div className="st-fadein">
          <DeviceManagement />
        </div>
      </StudentPageShell>
    </RoleGuard>
  );
}
