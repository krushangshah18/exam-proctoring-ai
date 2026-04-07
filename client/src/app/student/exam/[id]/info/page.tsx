"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter, useParams } from "next/navigation";
import {
  ShieldAlert,
  Clock,
  Loader2,
  ArrowRight,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  BookOpen,
  MessageSquare,
  History,
  RefreshCw,
  Ban,
  RotateCcw,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/axios";
import { parseUTC, fmtDateTimeTZ, fmtDateTimeTZFromDate } from "@/lib/fmt-date";

function InfoCard({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        background: "#fff",
        border: "1.5px solid #CBD5E1",
        borderRadius: "16px",
        padding: "22px 24px",
        boxShadow: "0 12px 28px rgba(15, 23, 42, 0.05)",
      }}
    >
      {children}
    </div>
  );
}

function SectionTitle({ icon, text }: { icon: React.ReactNode; text: string }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        marginBottom: "18px",
      }}
    >
      {icon}
      <h3 style={{ fontSize: "15px", fontWeight: 700, color: "#0F172A" }}>
        {text}
      </h3>
    </div>
  );
}

const MONITORING_CHECK_LABELS: Record<string, string> = {
  audio_analysis: "Audio monitored",
  eye_gaze: "Looking away is monitored",
  tab_switching: "Tab switching not allowed",
  multiple_person: "Multiple persons not allowed",
  looking_away: "Looking away is monitored",
  phone_detected:
    "Prohibited objects monitored: phones, books, headphones, earbuds",
  book_detected:
    "Prohibited objects monitored: phones, books, headphones, earbuds",
  earphones: "Prohibited objects monitored: phones, books, headphones, earbuds",
};

const DETECTION_CHECK_LABELS: Record<string, string> = {
  DETECT_LOOKING_AWAY: "Looking away is monitored",
  DETECT_LOOKING_DOWN: "Looking away is monitored",
  DETECT_LOOKING_UP: "Looking away is monitored",
  DETECT_LOOKING_SIDE: "Looking away is monitored",
  DETECT_FACE_HIDDEN: "Face hidden detection enabled",
  DETECT_PARTIAL_FACE: "Partial face detection enabled",
  DETECT_SPEAKER_AUDIO: "Speaker audio detection enabled",
  DETECT_PHONE:
    "Prohibited objects monitored: phones, books, headphones, earbuds",
  DETECT_BOOK:
    "Prohibited objects monitored: phones, books, headphones, earbuds",
  DETECT_HEADPHONE:
    "Prohibited objects monitored: phones, books, headphones, earbuds",
  DETECT_EARBUD:
    "Prohibited objects monitored: phones, books, headphones, earbuds",
  DETECT_MULTIPLE_PEOPLE: "Multiple persons not allowed",
};

const HIDDEN_PROCTORING_KEYS = new Set([
  "static_photo",
  "DETECT_FACE_HIDDEN",
  "DETECT_PARTIAL_FACE",
  "DETECT_FAKE_PRESENCE",
  "DETECT_SPEAKER_AUDIO",
]);

export default function ExamInfoPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [exam, setExam] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [appealReason, setAppealReason] = useState("");
  const [submittingAppeal, setSubmittingAppeal] = useState(false);

  const gatewayTidRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const appealPending = exam?.active_resume_request?.status === "PENDING";
  const appealApproved = exam?.active_resume_request?.status === "APPROVED";
  const sessionStatus = exam?.session_status as string | null;

  // Auto-redirect when late-join appeal gets approved
  useEffect(() => {
    if (appealApproved && exam?.is_late) {
      toast.success("Your appeal was approved! Proceeding to exam setup...");
      setTimeout(() => router.push(`/student/exam/${examId}/device`), 1500);
    }
  }, [appealApproved, exam?.is_late, examId, router]);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await api.get(`/exam/${examId}/status`);
      const data = res.data;
      setExam(data);
      if (!data.allowed_to_enter && data.time_until_open_ms > 0) {
        if (gatewayTidRef.current) clearTimeout(gatewayTidRef.current);
        gatewayTidRef.current = setTimeout(
          fetchStatus,
          data.time_until_open_ms + 1000,
        );
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to fetch exam status");
    } finally {
      setLoading(false);
    }
  }, [examId]);

  const pollInterval = appealPending || appealApproved
    ? 5000
    : sessionStatus === "DISCONNECTED"
      ? 10000
      : 60000;

  useEffect(() => {
    if (!examId) return;
    fetchStatus();
    const id = setInterval(fetchStatus, pollInterval);
    return () => {
      clearInterval(id);
      if (gatewayTidRef.current) clearTimeout(gatewayTidRef.current);
    };
  }, [examId, fetchStatus, pollInterval]);

  const handleAppealSubmit = async () => {
    const reason = `Late joining: ${appealReason}`;
    if (!reason.trim()) return toast.error("Please enter a reason.");
    setSubmittingAppeal(true);
    try {
      await api.post(`/exam/${examId}/appeal`, { reason });
      toast.success("Appeal submitted successfully.");
      await fetchStatus();
    } catch (err: any) {
      toast.error(err.response?.data?.detail || "Failed to submit appeal");
    } finally {
      setSubmittingAppeal(false);
    }
  };

  if (loading) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Loader2
          style={{
            width: "28px",
            height: "28px",
            color: "#22577A",
            animation: "spin 1s linear infinite",
          }}
        />
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "24px",
        }}
      >
        <div style={{ textAlign: "center", maxWidth: "380px" }}>
          <ShieldAlert
            style={{
              width: "48px",
              height: "48px",
              color: "#EF4444",
              margin: "0 auto 16px",
            }}
          />
          <h2
            style={{
              fontSize: "20px",
              fontWeight: 800,
              color: "#0F172A",
              marginBottom: "8px",
            }}
          >
            Access Denied
          </h2>
          <p
            style={{ fontSize: "14px", color: "#64748B", marginBottom: "20px" }}
          >
            {error}
          </p>
          <button
            onClick={() => router.push("/student/dashboard")}
            className="st-btn-ghost"
          >
            Return to Dashboard
          </button>
        </div>
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  const startTime = parseUTC(exam.start_window);
  const endTime = exam.end_window ? parseUTC(exam.end_window) : null;
  const examEnded = endTime ? new Date() >= endTime : false;
  const deadlineTime = exam.hard_join_deadline
    ? parseUTC(exam.hard_join_deadline)
    : null;
  const gatewayTime = new Date(startTime.getTime() - 15 * 60000);
  const proctoringChecks = [
    ...Object.entries(exam.config ?? {})
      .filter(
        ([key, enabled]) =>
          Boolean(enabled) && !HIDDEN_PROCTORING_KEYS.has(key),
      )
      .map(([key]) => MONITORING_CHECK_LABELS[key] ?? key.replace(/_/g, " ")),
    ...Object.entries(exam.detection_config ?? {})
      .filter(
        ([key, enabled]) =>
          Boolean(enabled) && !HIDDEN_PROCTORING_KEYS.has(key),
      )
      .map(([key]) => DETECTION_CHECK_LABELS[key] ?? key.replace(/_/g, " ")),
  ].filter((label, index, list) => list.indexOf(label) === index);

  const renderCTA = () => {
    if (sessionStatus === "ACTIVE") {
      return (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "16px",
            padding: "20px 24px",
            background: "rgba(34,87,122,0.06)",
            borderRadius: "12px",
            border: "1.5px solid rgba(34,87,122,0.2)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            <div
              style={{
                width: "40px",
                height: "40px",
                borderRadius: "10px",
                background: "rgba(34,87,122,0.1)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <RefreshCw
                style={{ width: "18px", height: "18px", color: "#22577A" }}
              />
            </div>
            <div>
              <h4
                style={{
                  fontSize: "14.5px",
                  fontWeight: 700,
                  color: "#22577A",
                }}
              >
                Exam Session Active
              </h4>
              <p
                style={{ fontSize: "13px", color: "#38A3A5", marginTop: "2px" }}
              >
                You have an ongoing exam session. Return to it now.
              </p>
            </div>
          </div>
          <button
            onClick={() => router.push(`/student/exam/${examId}/active`)}
            className="st-btn"
            style={{ flexShrink: 0 }}
          >
            Return to Exam{" "}
            <ArrowRight style={{ width: "14px", height: "14px" }} />
          </button>
        </div>
      );
    }

    if (sessionStatus === "DISCONNECTED") {
      return (
        <div
          style={{
            padding: "20px 24px",
            background: "rgba(245,158,11,0.06)",
            borderRadius: "12px",
            border: "2px solid rgba(245,158,11,0.35)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "14px",
              marginBottom: "16px",
            }}
          >
            <AlertTriangle
              style={{
                width: "22px",
                height: "22px",
                color: "#D97706",
                flexShrink: 0,
                marginTop: "1px",
              }}
            />
            <div>
              <h4
                style={{ fontSize: "15px", fontWeight: 700, color: "#92400E" }}
              >
                Your Exam Is Still In Progress!
              </h4>
              <p
                style={{
                  fontSize: "13px",
                  color: "#B45309",
                  lineHeight: 1.55,
                  marginTop: "4px",
                }}
              >
                Don't worry — your session and all your work are saved. Your
                connection dropped, but the exam is still running. Complete the
                setup checks quickly to rejoin.
              </p>
            </div>
          </div>
          <button
            onClick={() => router.push(`/student/exam/${examId}/device`)}
            className="st-btn st-btn-warning"
            style={{ width: "100%", padding: "12px" }}
          >
            <RotateCcw style={{ width: "16px", height: "16px" }} /> Start
            Reconnect Setup
          </button>
          <p
            style={{
              fontSize: "11.5px",
              color: "#D97706",
              textAlign: "center",
              marginTop: "10px",
            }}
          >
            Checking for status updates every 10 seconds…
          </p>
        </div>
      );
    }

    if (sessionStatus === "TERMINATED") {
      return (
        <div
          style={{
            padding: "20px 24px",
            background: "rgba(239,68,68,0.05)",
            borderRadius: "12px",
            border: "1.5px solid rgba(239,68,68,0.2)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "12px",
              marginBottom: "16px",
            }}
          >
            <Ban
              style={{
                width: "20px",
                height: "20px",
                color: "#EF4444",
                flexShrink: 0,
                marginTop: "1px",
              }}
            />
            <div>
              <h4
                style={{ fontSize: "15px", fontWeight: 700, color: "#991B1B" }}
              >
                Session Terminated
              </h4>
              <p
                style={{
                  fontSize: "13px",
                  color: "#DC2626",
                  lineHeight: 1.55,
                  marginTop: "3px",
                }}
              >
                Your exam session has been terminated. If you believe this was
                an error, you can request access from the terminated session
                page.
              </p>
            </div>
          </div>
          <div style={{ display: "flex", gap: "10px" }}>
            <button
              onClick={() => router.push(`/student/exam/${examId}/terminated`)}
              className="st-btn st-btn-danger"
              style={{ flex: 1 }}
            >
              <MessageSquare style={{ width: "14px", height: "14px" }} />{" "}
              Request Access
            </button>
            <button
              onClick={() => router.push("/student/dashboard")}
              className="st-btn-ghost"
              style={{ flex: 1 }}
            >
              Back to Dashboard
            </button>
          </div>
        </div>
      );
    }

    if (sessionStatus === "ENDED") {
      return (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "16px",
            padding: "20px 24px",
            background: "rgba(34,197,94,0.05)",
            borderRadius: "12px",
            border: "1.5px solid rgba(34,197,94,0.2)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            <CheckCircle2
              style={{
                width: "22px",
                height: "22px",
                color: "#22C55E",
                flexShrink: 0,
              }}
            />
            <div>
              <h4
                style={{
                  fontSize: "14.5px",
                  fontWeight: 700,
                  color: "#15803D",
                }}
              >
                Exam Already Submitted
              </h4>
              <p
                style={{ fontSize: "13px", color: "#16A34A", marginTop: "2px" }}
              >
                You have already completed and submitted this exam.
              </p>
            </div>
          </div>
          <button
            onClick={() => router.push("/student/history")}
            className="st-btn-ghost"
            style={{ flexShrink: 0 }}
          >
            <History style={{ width: "14px", height: "14px" }} /> View History
          </button>
        </div>
      );
    }

    if (examEnded && sessionStatus !== "ACTIVE" && sessionStatus !== "ENDED") {
      return (
        <div
          style={{
            padding: "20px 24px",
            background: "rgba(100,116,139,0.06)",
            borderRadius: "12px",
            border: "1.5px solid rgba(100,116,139,0.2)",
            display: "flex",
            alignItems: "flex-start",
            gap: "12px",
          }}
        >
          <XCircle style={{ width: "20px", height: "20px", color: "#64748B", flexShrink: 0, marginTop: "1px" }} />
          <div>
            <h4 style={{ fontSize: "15px", fontWeight: 700, color: "#334155" }}>
              Exam Has Ended
            </h4>
            <p style={{ fontSize: "13px", color: "#64748B", marginTop: "3px", lineHeight: 1.55 }}>
              This exam's window has closed. You are no longer able to enter.
            </p>
            <button
              onClick={() => router.push("/student/dashboard")}
              className="st-btn-ghost"
              style={{ marginTop: "12px" }}
            >
              Back to Dashboard
            </button>
          </div>
        </div>
      );
    }

    if (exam.is_late && exam.active_resume_request?.status !== "APPROVED") {
      return (
        <div
          style={{
            padding: "20px 24px",
            background: "rgba(239,68,68,0.05)",
            borderRadius: "12px",
            border: "1.5px solid rgba(239,68,68,0.2)",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              marginBottom: "14px",
            }}
          >
            <ShieldAlert
              style={{ width: "18px", height: "18px", color: "#EF4444" }}
            />
            <h4 style={{ fontSize: "15px", fontWeight: 700, color: "#991B1B" }}>
              Hard Deadline Passed
            </h4>
          </div>

          {exam.late_join_policy === "DENY" && (
            <p style={{ fontSize: "13.5px", color: "#DC2626" }}>
              This exam strictly denies late joins. You may no longer enter.
            </p>
          )}

          {exam.late_join_policy === "REVIEW" &&
            !exam.active_resume_request && (
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "12px",
                }}
              >
                <p style={{ fontSize: "13.5px", color: "#DC2626" }}>
                  You missed the join window. Submit an appeal to request late
                  entry.
                </p>
                <textarea
                  placeholder="Explain clearly why you are late..."
                  value={appealReason}
                  onChange={(e) => setAppealReason(e.target.value)}
                  className="st-textarea"
                />
                <button
                  onClick={handleAppealSubmit}
                  disabled={submittingAppeal}
                  className="st-btn st-btn-danger"
                >
                  {submittingAppeal && (
                    <Loader2
                      style={{
                        width: "14px",
                        height: "14px",
                        animation: "spin 1s linear infinite",
                      }}
                    />
                  )}
                  Submit Appeal
                </button>
              </div>
            )}

          {exam.late_join_policy === "REVIEW" &&
            exam.active_resume_request?.status === "PENDING" && (
              <div
                style={{
                  padding: "14px 16px",
                  background: "rgba(255,255,255,0.5)",
                  borderRadius: "8px",
                  border: "1px solid rgba(239,68,68,0.15)",
                }}
              >
                <p
                  style={{
                    fontSize: "13.5px",
                    color: "#991B1B",
                    fontWeight: 600,
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <Loader2
                    style={{
                      width: "14px",
                      height: "14px",
                      animation: "spin 1s linear infinite",
                    }}
                  />
                  Your appeal is under review — checking every 5 seconds
                </p>
                <p
                  style={{
                    fontSize: "13px",
                    color: "#DC2626",
                    fontStyle: "italic",
                    marginTop: "6px",
                  }}
                >
                  "{exam.active_resume_request.reason}"
                </p>
                <p
                  style={{
                    fontSize: "11.5px",
                    color: "#94A3B8",
                    marginTop: "6px",
                  }}
                >
                  Please keep this page open. Do not close the browser.
                </p>
              </div>
            )}

          {exam.late_join_policy === "REVIEW" &&
            exam.active_resume_request?.status === "APPROVED" && (
              <div
                style={{
                  padding: "14px 16px",
                  background: "rgba(34,197,94,0.08)",
                  borderRadius: "8px",
                  border: "1px solid rgba(34,197,94,0.3)",
                }}
              >
                <p
                  style={{
                    fontSize: "13.5px",
                    color: "#166534",
                    fontWeight: 700,
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}
                >
                  <CheckCircle2 style={{ width: "15px", height: "15px" }} />
                  Your appeal was approved! Redirecting to exam setup...
                </p>
                <button
                  onClick={() => router.push(`/student/exam/${examId}/device`)}
                  className="st-btn st-btn-primary"
                  style={{ marginTop: "10px" }}
                >
                  Proceed to Setup <ArrowRight style={{ width: "14px", height: "14px" }} />
                </button>
              </div>
            )}

          {exam.late_join_policy === "REVIEW" &&
            exam.active_resume_request?.status === "DENIED" && (
              <div
                style={{
                  padding: "14px 16px",
                  background: "rgba(255,255,255,0.5)",
                  borderRadius: "8px",
                  border: "1px solid rgba(239,68,68,0.15)",
                }}
              >
                <p
                  style={{
                    fontSize: "13.5px",
                    fontWeight: 700,
                    color: "#991B1B",
                  }}
                >
                  Your appeal was denied.
                </p>
                {exam.active_resume_request.review_note && (
                  <p
                    style={{
                      fontSize: "13px",
                      color: "#DC2626",
                      marginTop: "4px",
                    }}
                  >
                    Note: {exam.active_resume_request.review_note}
                  </p>
                )}
              </div>
            )}
        </div>
      );
    }

    if (!exam.allowed_to_enter) {
      const msLeft = exam.time_until_open_ms ?? 0;
      const minsLeft = Math.ceil(msLeft / 60000);
      return (
        <div
          style={{
            padding: "18px 20px",
            background: "rgba(245,158,11,0.06)",
            borderRadius: "12px",
            border: "1.5px solid rgba(245,158,11,0.25)",
            display: "flex",
            alignItems: "flex-start",
            gap: "12px",
          }}
        >
          <Clock
            style={{
              width: "18px",
              height: "18px",
              color: "#D97706",
              flexShrink: 0,
              marginTop: "2px",
            }}
          />
          <div>
            <p
              style={{
                fontSize: "14px",
                fontWeight: 700,
                color: "#92400E",
                marginBottom: "4px",
              }}
            >
              Gateway Locked
            </p>
            <p style={{ fontSize: "13px", color: "#B45309", lineHeight: 1.55 }}>
              The setup gateway opens 15 minutes before the exam starts. You can
              proceed from <strong>{fmtDateTimeTZFromDate(gatewayTime)}</strong>
              {minsLeft > 1 &&
                ` (in about ${minsLeft} minute${minsLeft !== 1 ? "s" : ""})`}
              . This page will automatically unlock — no refresh needed.
            </p>
          </div>
        </div>
      );
    }

    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: "16px",
          padding: "20px 24px",
          background: "rgba(34,87,122,0.05)",
          borderRadius: "12px",
          border: "1.5px solid rgba(34,87,122,0.2)",
        }}
      >
        <div>
          <h4 style={{ fontSize: "14.5px", fontWeight: 700, color: "#22577A" }}>
            Setup Gateway Open
          </h4>
          <p style={{ fontSize: "13px", color: "#38A3A5", marginTop: "2px" }}>
            Proceed with camera, microphone, and environment checks.
          </p>
        </div>
        <button
          onClick={() => router.push(`/student/exam/${examId}/device`)}
          className="st-btn"
          style={{ flexShrink: 0 }}
        >
          Start Setup <ArrowRight style={{ width: "14px", height: "14px" }} />
        </button>
      </div>
    );
  };

  return (
    <>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "32px 28px 40px",
          background: "linear-gradient(180deg, #EAF2F7 0%, #F4F8FB 100%)",
        }}
      >
        <div
          style={{
            maxWidth: "1180px",
            margin: "0 auto",
            display: "flex",
            flexDirection: "column",
            gap: "20px",
          }}
          className="st-fadein"
        >
          {/* Header */}
          <div
            style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              gap: "16px",
              padding: "26px 28px",
              borderRadius: "20px",
              background:
                "linear-gradient(135deg, #22577A 0%, #2E7DA4 55%, #38A3A5 100%)",
              boxShadow: "0 18px 40px rgba(34, 87, 122, 0.16)",
              position: "relative",
              overflow: "hidden",
            }}
          >
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
            <div
              style={{
                position: "absolute",
                right: "-18px",
                bottom: "-18px",
                opacity: 0.08,
                pointerEvents: "none",
              }}
            >
              <BookOpen
                style={{ width: "140px", height: "140px", color: "#fff" }}
              />
            </div>
            <div
              style={{ position: "relative", zIndex: 1, flex: 1, minWidth: 0 }}
            >
              <p
                style={{
                  fontSize: "11.5px",
                  fontWeight: 700,
                  color: "rgba(255,255,255,0.62)",
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  marginBottom: "8px",
                }}
              >
                Exam Information
              </p>
              <h1
                style={{
                  fontSize: "28px",
                  fontWeight: 800,
                  color: "#fff",
                  letterSpacing: "-0.03em",
                  marginBottom: "6px",
                  lineHeight: 1.15,
                }}
              >
                {exam.title}
              </h1>
              <p
                style={{
                  fontSize: "14px",
                  color: "rgba(255,255,255,0.8)",
                  lineHeight: 1.6,
                  maxWidth: "760px",
                }}
              >
                Review the schedule, active monitoring rules, and entry status
                before you begin the setup steps.
              </p>
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "minmax(0, 1.55fr) minmax(320px, 0.95fr)",
              gap: "20px",
              alignItems: "start",
            }}
          >
            <div
              style={{ display: "flex", flexDirection: "column", gap: "18px" }}
            >
              {/* Exam Details */}
              <InfoCard>
                <SectionTitle
                  icon={
                    <Info
                      style={{
                        width: "16px",
                        height: "16px",
                        color: "#22577A",
                      }}
                    />
                  }
                  text="Exam Details"
                />
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
                    gap: "18px 32px",
                  }}
                >
                  {[
                    {
                      label: "Duration",
                      value: `${exam.duration_minutes} minutes`,
                    },
                    {
                      label: "Starts At",
                      value: fmtDateTimeTZ(exam.start_window),
                    },
                    { label: "Ends At", value: fmtDateTimeTZ(exam.end_window) },
                    ...(deadlineTime
                      ? [
                          {
                            label: "Join Deadline",
                            value: fmtDateTimeTZ(exam.hard_join_deadline),
                            color: "#DC2626",
                          },
                        ]
                      : []),
                  ].map(({ label, value, color }: any) => (
                    <div key={label}>
                      <p
                        style={{
                          fontSize: "10.5px",
                          fontWeight: 700,
                          color: "#64748B",
                          textTransform: "uppercase",
                          letterSpacing: "0.07em",
                          marginBottom: "4px",
                        }}
                      >
                        {label}
                      </p>
                      <p
                        style={{
                          fontSize: "14px",
                          fontWeight: 700,
                          color: color || "#0F172A",
                          lineHeight: 1.5,
                        }}
                      >
                        {value}
                      </p>
                    </div>
                  ))}
                </div>
              </InfoCard>

              {/* Proctoring Rules */}
              {proctoringChecks.length > 0 && (
                <InfoCard>
                  <SectionTitle
                    icon={
                      <ShieldAlert
                        style={{
                          width: "16px",
                          height: "16px",
                          color: "#F59E0B",
                        }}
                      />
                    }
                    text="Proctoring Active"
                  />
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(auto-fill, minmax(240px, 1fr))",
                      gap: "10px",
                    }}
                  >
                    {proctoringChecks.map((label) => {
                      const isBlueRule = /audio monitored/i.test(label);
                      const isStrictRule =
                        /tab|multiple|phone|book|headphone|earbud|looking/i.test(
                          label,
                        ) || isBlueRule;

                      return (
                        <div
                          key={label}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "10px",
                            background: isStrictRule
                              ? "rgba(34,87,122,0.06)"
                              : "#F8FAFC",
                            padding: "11px 14px",
                            borderRadius: "10px",
                            border: isStrictRule
                              ? "1px solid rgba(34,87,122,0.18)"
                              : "1px solid #CBD5E1",
                          }}
                        >
                          {isStrictRule ? (
                            <ShieldAlert
                              style={{
                                width: "15px",
                                height: "15px",
                                color: "#22577A",
                                flexShrink: 0,
                                marginTop: "2px",
                              }}
                            />
                          ) : (
                            <CheckCircle2
                              style={{
                                width: "15px",
                                height: "15px",
                                color: "#22577A",
                                flexShrink: 0,
                                marginTop: "2px",
                              }}
                            />
                          )}
                          <span
                            style={{
                              fontSize: "13px",
                              fontWeight: 600,
                              color: isStrictRule ? "#22577A" : "#475569",
                              lineHeight: 1.5,
                            }}
                          >
                            {label}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </InfoCard>
              )}

              {/* Rules */}
              <InfoCard>
                <SectionTitle
                  icon={
                    <BookOpen
                      style={{
                        width: "16px",
                        height: "16px",
                        color: "#22577A",
                      }}
                    />
                  }
                  text="Rules & Guidelines"
                />
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "1fr 1fr",
                    gap: "24px",
                  }}
                >
                  <div>
                    <p
                      style={{
                        fontSize: "11px",
                        fontWeight: 700,
                        color: "#16A34A",
                        textTransform: "uppercase",
                        letterSpacing: "0.09em",
                        marginBottom: "10px",
                      }}
                    >
                      DO
                    </p>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "8px",
                      }}
                    >
                      {[
                        "Ensure your face is clearly visible throughout",
                        "Sit in a well-lit, quiet room with a plain background",
                        "Keep your ID document nearby if required",
                        "Stay within the exam window — do not minimize or switch tabs",
                        "Use a stable internet connection",
                        "Test your camera and microphone beforehand",
                      ].map((item) => (
                        <div
                          key={item}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "8px",
                          }}
                        >
                          <CheckCircle2
                            style={{
                              width: "13px",
                              height: "13px",
                              color: "#22C55E",
                              flexShrink: 0,
                              marginTop: "2px",
                            }}
                          />
                          <p
                            style={{
                              fontSize: "13px",
                              color: "#475569",
                              lineHeight: 1.5,
                            }}
                          >
                            {item}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p
                      style={{
                        fontSize: "11px",
                        fontWeight: 700,
                        color: "#DC2626",
                        textTransform: "uppercase",
                        letterSpacing: "0.09em",
                        marginBottom: "10px",
                      }}
                    >
                      DON'T
                    </p>
                    <div
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        gap: "8px",
                      }}
                    >
                      {[
                        "Do not use a second monitor or device",
                        "Do not allow other people in the room",
                        "Do not cover your face with hands or headwear",
                        "Do not use headphones or earphones",
                        "Do not open other applications or browser tabs",
                      ].map((item) => (
                        <div
                          key={item}
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "8px",
                          }}
                        >
                          <XCircle
                            style={{
                              width: "13px",
                              height: "13px",
                              color: "#EF4444",
                              flexShrink: 0,
                              marginTop: "2px",
                            }}
                          />
                          <p
                            style={{
                              fontSize: "13px",
                              color: "#475569",
                              lineHeight: 1.5,
                            }}
                          >
                            {item}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </InfoCard>
            </div>

            <div
              style={{ display: "flex", flexDirection: "column", gap: "18px" }}
            >
              {/* CTA */}
              {renderCTA()}

              {/* Room Checklist */}
              <div
                style={{
                  padding: "18px 20px",
                  background: "rgba(34,87,122,0.04)",
                  borderRadius: "16px",
                  border: "1.5px solid rgba(34,87,122,0.14)",
                  boxShadow: "0 10px 22px rgba(15,23,42,0.04)",
                }}
              >
                <h4
                  style={{
                    fontSize: "13.5px",
                    fontWeight: 700,
                    color: "#22577A",
                    marginBottom: "10px",
                    display: "flex",
                    alignItems: "center",
                    gap: "7px",
                  }}
                >
                  <Info style={{ width: "14px", height: "14px" }} /> Room &
                  Environment Checklist
                </h4>
                <ul
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: "5px",
                  }}
                >
                  {[
                    "Position yourself facing the light source (window/lamp in front, not behind)",
                    "Ensure the background is a plain wall or uncluttered surface",
                    "Minimize background noise — close doors, silence phones",
                    "Do not have books, notes, or papers on your desk",
                  ].map((item) => (
                    <li
                      key={item}
                      style={{
                        fontSize: "13px",
                        color: "#22577A",
                        display: "flex",
                        gap: "7px",
                        lineHeight: 1.55,
                      }}
                    >
                      <span style={{ color: "#38A3A5" }}>•</span> {item}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Appeals info */}
              <div
                style={{
                  padding: "16px 20px",
                  background: "#F8FAFC",
                  borderRadius: "16px",
                  border: "1.5px solid #CBD5E1",
                  boxShadow: "0 10px 22px rgba(15,23,42,0.04)",
                }}
              >
                <h4
                  style={{
                    fontSize: "13.5px",
                    fontWeight: 700,
                    color: "#475569",
                    marginBottom: "6px",
                    display: "flex",
                    alignItems: "center",
                    gap: "7px",
                  }}
                >
                  <MessageSquare style={{ width: "14px", height: "14px" }} />{" "}
                  About Appeals
                </h4>
                <p
                  style={{
                    fontSize: "13px",
                    color: "#64748B",
                    lineHeight: 1.6,
                  }}
                >
                  If your session is unexpectedly terminated or you believe a
                  system flag was raised in error, you may submit an appeal. An
                  admin will review it and can approve your re-entry.{" "}
                  <strong style={{ color: "#475569" }}>
                    Do not close the browser
                  </strong>{" "}
                  while your appeal is pending.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
