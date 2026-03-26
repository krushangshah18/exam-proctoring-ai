"use client";

import { useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';
import { fmtDate, fmtTimeTZ } from '@/lib/fmt-date';
import { Plus, Calendar, Clock, Users, ChevronRight } from 'lucide-react';
import { SearchInput } from '@/components/common/SearchInput';
import { DataTable } from '@/components/common/DataTable';
import { ColumnDef, PaginationState } from '@tanstack/react-table';

const PAGE_SIZE = 10;

interface Exam {
  id: string;
  title: string;
  exam_mode: string;
  status: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  created_at: string;
  invite_count: number;
}

const STATUS_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  LIVE:      { bg: '#ECFDF5', color: '#15803D', border: '#BBF7D0' },
  SCHEDULED: { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE' },
  ENDED:     { bg: '#F8FAFC', color: '#475569', border: '#E2E8F0' },
  CANCELLED: { bg: '#FFF1F2', color: '#BE123C', border: '#FECDD3' },
  DRAFT:     { bg: '#F8FAFC', color: '#64748B', border: '#E2E8F0' },
  COMPLETED: { bg: '#EFF6FF', color: '#1D4ED8', border: '#BFDBFE' },
};

export default function AdminExamsPage() {
  const router = useRouter();
  const [exams, setExams] = useState<Exam[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);

  useEffect(() => { fetchExams(); }, []);

  const fetchExams = async () => {
    try {
      setLoading(true);
      const res = await api.get('/admin/exams');
      setExams(res.data);
    } catch (error) {
      console.error("Failed to fetch exams", error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = useCallback((val: string) => {
    setSearch(val);
    setPage(1);
  }, []);

  const filteredExams = exams.filter(e => e.title.toLowerCase().includes(search.toLowerCase()));
  const totalPages = Math.max(1, Math.ceil(filteredExams.length / pageSize));
  const pagedExams = filteredExams.slice((page - 1) * pageSize, page * pageSize);

  const pagination: PaginationState = useMemo(() => ({
    pageIndex: page - 1,
    pageSize,
  }), [page, pageSize]);

  const handlePaginationChange = useCallback((updater: PaginationState | ((old: PaginationState) => PaginationState)) => {
    const next = typeof updater === 'function' ? updater(pagination) : updater;
    if (next.pageSize !== pageSize) {
      setPageSize(next.pageSize);
      setPage(1);
      return;
    }
    if (next.pageIndex + 1 !== page) setPage(next.pageIndex + 1);
  }, [page, pageSize, pagination]);

  const columns = useMemo<ColumnDef<Exam>[]>(() => [
    {
      accessorKey: 'title',
      header: 'Exam Details',
      cell: ({ row }) => {
        const s = STATUS_STYLES[row.original.status] ?? STATUS_STYLES.DRAFT;
        return (
          <div className="flex flex-col gap-1 py-1">
            <span className="font-semibold text-sm" style={{ color: '#0F172A' }}>{row.original.title}</span>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold border"
                style={{ background: '#F8FAFC', color: '#64748B', borderColor: '#E2E8F0' }}>
                {row.original.exam_mode}
              </span>
              <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold border"
                style={{ background: s.bg, color: s.color, borderColor: s.border }}>
                {row.original.status}
              </span>
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'start_window',
      header: 'Schedule',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-sm" style={{ color: '#475569' }}>
          <Calendar className="h-3.5 w-3.5" style={{ color: '#CBD5E1' }} />
          <span>{fmtDate(row.original.start_window)}, {fmtTimeTZ(row.original.start_window)}</span>
        </div>
      ),
    },
    {
      accessorKey: 'duration_minutes',
      header: 'Duration',
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5 text-sm" style={{ color: '#475569' }}>
          <Clock className="h-4 w-4" style={{ color: '#CBD5E1' }} />
          <span>{row.original.duration_minutes} min</span>
        </div>
      ),
    },
    {
      accessorKey: 'invite_count',
      header: 'Students',
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5 text-sm" style={{ color: '#475569' }}>
          <Users className="h-4 w-4" style={{ color: '#CBD5E1' }} />
          <span className="font-medium">{row.original.invite_count}</span>
        </div>
      ),
    },
    {
      id: 'actions',
      header: '',
      cell: ({ row }) => (
        <div className="text-right">
          <button
            onClick={() => router.push(`/admin/dashboard/exams/${row.original.id}`)}
            className="h-8 w-8 flex items-center justify-center rounded-lg border transition-all duration-150 ml-auto"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#EFF6FF'; (e.currentTarget as HTMLElement).style.borderColor = '#22577A'; (e.currentTarget as HTMLElement).style.color = '#22577A'; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#fff'; (e.currentTarget as HTMLElement).style.borderColor = '#E2E8F0'; (e.currentTarget as HTMLElement).style.color = '#475569'; }}
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ], [router]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>Exams</h1>
          <p className="text-sm mt-1" style={{ color: '#94A3B8' }}>Manage and monitor all your proctored examinations.</p>
        </div>
        <button
          onClick={() => router.push('/admin/dashboard/exams/new')}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold text-white transition-all duration-150"
          style={{ background: '#22577A' }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.background = '#1a4560'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.background = '#22577A'}
        >
          <Plus className="h-4 w-4" /> Create Exam
        </button>
      </div>

      <div className="flex items-center gap-4">
        <SearchInput
          placeholder="Search exams by title..."
          onSearch={handleSearch}
          isLoading={loading}
        />
      </div>

      <DataTable
        columns={columns}
        data={pagedExams}
        pageCount={totalPages}
        pagination={pagination}
        onPaginationChange={handlePaginationChange}
        isLoading={loading}
        totalItems={filteredExams.length}
      />
    </div>
  );
}
