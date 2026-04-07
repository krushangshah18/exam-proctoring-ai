"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  FileText,
  Loader2,
  RefreshCw,
  Calendar,
  Clock,
  Users,
  ChevronRight,
  Search,
} from "lucide-react";
import api from "@/lib/axios";
import { TablePagination } from "@/components/common/TablePagination";

interface ExamSummary {
  id: string;
  title: string;
  exam_mode: string;
  status: string;
  start_window: string;
  end_window: string;
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
  COMPLETED: { bg: "#EFF6FF", color: "#1D4ED8", border: "#BFDBFE" },
};

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export default function AdminReportsPage() {
  const router = useRouter();
  const [exams, setExams] = useState<ExamSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const fetchExams = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get("/admin/exams");
      setExams(res.data);
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchExams();
  }, [fetchExams]);

  const filtered = exams.filter((e) =>
    e.title.toLowerCase().includes(search.toLowerCase()),
  );
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pagedExams = filtered.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => {
    setPage(1);
  }, [search]);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  return (
    <div className="space-y-6 pb-10 max-w-4xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1
            className="text-2xl font-bold"
            style={{ color: "#0F172A", letterSpacing: "-0.025em" }}
          >
            Reports
          </h1>
          <p className="text-sm mt-1" style={{ color: "#64748B" }}>
            View session reports for each exam.
          </p>
        </div>
        <button
          onClick={fetchExams}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
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
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search
          className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4"
          style={{ color: "#CBD5E1" }}
        />
        <input
          type="text"
          placeholder="Search exams..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full py-2.5 text-sm rounded-lg border outline-none transition-all"
          style={{
            borderColor: "#E2E8F0",
            color: "#0F172A",
            paddingLeft: "2.5rem",
            paddingRight: "0.75rem",
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

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-24">
          <Loader2
            className="h-7 w-7 animate-spin"
            style={{ color: "#CBD5E1" }}
          />
        </div>
      ) : filtered.length === 0 ? (
        <div
          className="bg-white rounded-xl border py-16 text-center"
          style={{
            borderColor: "#E2E8F0",
            boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
          }}
        >
          <FileText
            className="h-12 w-12 mx-auto mb-3"
            style={{ color: "#E2E8F0" }}
          />
          <p className="text-sm font-medium" style={{ color: "#475569" }}>
            {search ? "No exams match your search." : "No exams found."}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="space-y-2">
            {pagedExams.map((exam) => {
              const s = STATUS_STYLES[exam.status] ?? STATUS_STYLES.DRAFT;
              return (
                <div
                  key={exam.id}
                  className="bg-white rounded-xl border p-4 cursor-pointer transition-all duration-150"
                  style={{
                    borderColor: "#E2E8F0",
                    boxShadow: "0 1px 3px rgba(15,23,42,0.04)",
                  }}
                  onClick={() =>
                    router.push(`/admin/dashboard/exams/${exam.id}/reports`)
                  }
                  onMouseEnter={(e) =>
                    ((e.currentTarget as HTMLElement).style.boxShadow =
                      "0 4px 12px rgba(15,23,42,0.08)")
                  }
                  onMouseLeave={(e) =>
                    ((e.currentTarget as HTMLElement).style.boxShadow =
                      "0 1px 3px rgba(15,23,42,0.04)")
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
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <p
                          className="font-semibold text-sm"
                          style={{ color: "#0F172A" }}
                        >
                          {exam.title}
                        </p>
                        <span
                          className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                          style={{
                            background: s.bg,
                            color: s.color,
                            borderColor: s.border,
                          }}
                        >
                          {exam.status}
                        </span>
                        <span
                          className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border"
                          style={{
                            background: "#F8FAFC",
                            color: "#64748B",
                            borderColor: "#E2E8F0",
                          }}
                        >
                          {exam.exam_mode}
                        </span>
                      </div>
                      <div
                        className="flex items-center gap-4 text-xs flex-wrap"
                        style={{ color: "#64748B" }}
                      >
                        <span className="flex items-center gap-1">
                          <Calendar className="h-3 w-3" />{" "}
                          {fmtDate(exam.start_window)}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" /> {exam.duration_minutes}{" "}
                          min
                        </span>
                        <span className="flex items-center gap-1">
                          <Users className="h-3 w-3" /> {exam.invite_count}{" "}
                          student{exam.invite_count !== 1 ? "s" : ""}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className="text-xs font-semibold hidden sm:block"
                        style={{ color: "#22577A" }}
                      >
                        View Reports
                      </span>
                      <ChevronRight
                        className="h-4 w-4"
                        style={{ color: "#CBD5E1" }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <TablePagination
            page={page}
            pageCount={totalPages}
            pageSize={pageSize}
            totalItems={filtered.length}
            onPageChange={setPage}
            onPageSizeChange={(next) => {
              setPageSize(next);
              setPage(1);
            }}
          />
        </div>
      )}
    </div>
  );
}
