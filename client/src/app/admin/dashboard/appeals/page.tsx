"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowLeft,
  AlertTriangle,
  ClipboardCheck,
  Loader2,
  MessageSquare,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import api from "@/lib/axios";

interface PendingAppeal {
  resume_request_id: string;
  exam_id: string;
  exam_title: string;
  session_id: string;
  student_name: string;
  student_email: string;
  reason: string;
  created_at: string;
  terminated_by: string | null;
  terminated_reason: string | null;
}

function fmtDateTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export default function AdminAppealsInboxPage() {
  const router = useRouter();
  const [appeals, setAppeals] = useState<PendingAppeal[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAppeals = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get("/admin/exams/pending-appeals");
      setAppeals(res.data);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAppeals();
    const intervalId = setInterval(fetchAppeals, 15000);
    return () => clearInterval(intervalId);
  }, [fetchAppeals]);

  return (
    <div className="space-y-6 pb-10 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => router.push("/admin/dashboard")}
            className="h-9 w-9 flex items-center justify-center rounded-lg border transition-all duration-150"
            style={{
              borderColor: "#E2E8F0",
              color: "#475569",
              background: "#fff",
            }}
            onMouseEnter={(e) =>
              ((e.currentTarget as HTMLElement).style.background = "#F8FAFC")
            }
            onMouseLeave={(e) =>
              ((e.currentTarget as HTMLElement).style.background = "#fff")
            }
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <h1
              className="text-2xl font-bold"
              style={{ color: "#0F172A", letterSpacing: "-0.025em" }}
            >
              Appeal Inbox
            </h1>
            <p className="text-sm mt-0.5" style={{ color: "#64748B" }}>
              Pending student appeals that need fast review.
            </p>
          </div>
        </div>
        <button
          onClick={fetchAppeals}
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

      {/* Count indicator */}
      <div
        className="bg-white rounded-xl border flex items-center gap-4 p-5"
        style={{
          borderColor: "#FDE68A",
          boxShadow: "0 0 0 3px rgba(245,158,11,0.08)",
        }}
      >
        <div
          className="h-12 w-12 rounded-full flex items-center justify-center shrink-0"
          style={{ background: "#FFFBEB" }}
        >
          <ClipboardCheck className="h-6 w-6" style={{ color: "#B45309" }} />
        </div>
        <div>
          <p
            className="text-2xl font-bold"
            style={{ color: "#0F172A", letterSpacing: "-0.03em" }}
          >
            {appeals.length}
          </p>
          <p className="text-sm" style={{ color: "#475569" }}>
            Pending appeal{appeals.length !== 1 ? "s" : ""} waiting for review
          </p>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center p-20">
          <Loader2
            className="h-7 w-7 animate-spin"
            style={{ color: "#CBD5E1" }}
          />
        </div>
      ) : appeals.length === 0 ? (
        <div
          className="bg-white rounded-xl border py-16 text-center"
          style={{
            borderColor: "#E2E8F0",
            boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
          }}
        >
          <MessageSquare
            className="h-12 w-12 mx-auto mb-3"
            style={{ color: "#E2E8F0" }}
          />
          <p className="font-medium text-sm" style={{ color: "#475569" }}>
            No pending appeals
          </p>
          <p className="text-xs mt-1" style={{ color: "#64748B" }}>
            This inbox updates automatically.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {appeals.map((appeal) => (
            <div
              key={appeal.resume_request_id}
              className="bg-white rounded-xl border overflow-hidden"
              style={{
                borderColor: "#E2E8F0",
                boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
              }}
            >
              {/* Card header */}
              <div
                className="flex flex-col md:flex-row md:items-start md:justify-between gap-3 px-5 py-4"
                style={{ borderBottom: "1px solid #F1F5F9" }}
              >
                <div>
                  <p className="font-semibold" style={{ color: "#0F172A" }}>
                    {appeal.student_name}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "#64748B" }}>
                    {appeal.student_email}
                  </p>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                    style={{
                      background: "#FFFBEB",
                      color: "#B45309",
                      borderColor: "#FDE68A",
                    }}
                  >
                    Pending
                  </span>
                  <span
                    className="inline-flex items-center px-2 py-0.5 rounded-md text-xs border"
                    style={{ borderColor: "#E2E8F0", color: "#64748B" }}
                  >
                    {fmtDateTime(appeal.created_at)}
                  </span>
                </div>
              </div>

              {/* Card content */}
              <div className="p-5 space-y-4">
                <div className="grid gap-3 md:grid-cols-2">
                  <div
                    className="rounded-lg border p-4"
                    style={{ background: "#F8FAFC", borderColor: "#E2E8F0" }}
                  >
                    <p
                      className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                      style={{ color: "#64748B" }}
                    >
                      Exam
                    </p>
                    <p
                      className="font-medium text-sm"
                      style={{ color: "#0F172A" }}
                    >
                      {appeal.exam_title}
                    </p>
                  </div>
                  <div
                    className="rounded-lg border p-4"
                    style={{ background: "#F8FAFC", borderColor: "#E2E8F0" }}
                  >
                    <p
                      className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                      style={{ color: "#64748B" }}
                    >
                      Termination
                    </p>
                    <p
                      className="font-medium text-sm"
                      style={{ color: "#0F172A" }}
                    >
                      {appeal.terminated_by || "Late Join"}
                    </p>
                    {appeal.terminated_reason && (
                      <p className="text-xs mt-1" style={{ color: "#475569" }}>
                        {appeal.terminated_reason}
                      </p>
                    )}
                  </div>
                </div>

                <div
                  className="rounded-lg border p-4 flex items-start gap-2"
                  style={{ background: "#FFFBEB", borderColor: "#FDE68A" }}
                >
                  <AlertTriangle
                    className="h-4 w-4 mt-0.5 shrink-0"
                    style={{ color: "#B45309" }}
                  />
                  <div>
                    <p
                      className="text-[10px] font-semibold uppercase tracking-wider mb-1"
                      style={{ color: "#B45309" }}
                    >
                      Student Appeal
                    </p>
                    <p
                      className="text-sm whitespace-pre-wrap"
                      style={{ color: "#475569" }}
                    >
                      {appeal.reason || "No reason provided."}
                    </p>
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={() =>
                      router.push(
                        `/admin/dashboard/exams/${appeal.exam_id}/monitor?tab=appeals`,
                      )
                    }
                    className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150"
                    style={{ background: "#22577A" }}
                    onMouseEnter={(e) =>
                      ((e.currentTarget as HTMLElement).style.background =
                        "#1a4560")
                    }
                    onMouseLeave={(e) =>
                      ((e.currentTarget as HTMLElement).style.background =
                        "#22577A")
                    }
                  >
                    Review In Monitor <ArrowRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
