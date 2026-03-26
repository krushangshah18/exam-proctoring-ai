"use client";

import { useEffect, useState, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';
import { fmtDate, fmtTimeTZ } from '@/lib/fmt-date';
import {
  Plus,
  Calendar,
  Clock,
  Users,
  ChevronRight
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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

export default function AdminExamsPage() {
  const router = useRouter();
  const [exams, setExams] = useState<Exam[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(PAGE_SIZE);

  useEffect(() => {
    fetchExams();
  }, []);

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

  const getStatusColor = (status: string) => {
    switch(status.toUpperCase()) {
      case 'LIVE': return 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20';
      case 'DRAFT': return 'bg-slate-500/10 text-slate-500 hover:bg-slate-500/20';
      case 'COMPLETED': return 'bg-blue-500/10 text-blue-500 hover:bg-blue-500/20';
      default: return 'bg-slate-500/10 text-slate-500';
    }
  };

  const pagination: PaginationState = useMemo(() => ({
    pageIndex: page - 1,
    pageSize,
  }), [page, pageSize]);

  const handlePaginationChange = useCallback((updater: PaginationState | ((old: PaginationState) => PaginationState)) => {
    const next = typeof updater === 'function' ? updater(pagination) : updater;
    const nextPage = next.pageIndex + 1;
    const nextPageSize = next.pageSize;

    if (nextPageSize !== pageSize) {
      setPageSize(nextPageSize);
      setPage(1);
      return;
    }

    if (nextPage !== page) {
      setPage(nextPage);
    }
  }, [page, pageSize, pagination]);

  const columns = useMemo<ColumnDef<Exam>[]>(() => [
    {
      accessorKey: 'title',
      header: 'Exam Details',
      cell: ({ row }) => (
        <div className="flex flex-col gap-1 py-1">
          <span className="font-semibold text-slate-900">{row.original.title}</span>
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="text-[10px] px-1.5 py-0 font-medium">
              {row.original.exam_mode}
            </Badge>
            <Badge className={getStatusColor(row.original.status)} variant="outline">
              {row.original.status}
            </Badge>
          </div>
        </div>
      ),
    },
    {
      accessorKey: 'start_window',
      header: 'Schedule',
      cell: ({ row }) => (
        <div className="flex items-center gap-2 text-slate-600">
          <Calendar className="h-3.5 w-3.5 text-slate-400" />
          <span>{fmtDate(row.original.start_window)}, {fmtTimeTZ(row.original.start_window)}</span>
        </div>
      ),
    },
    {
      accessorKey: 'duration_minutes',
      header: 'Duration',
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5 text-slate-600">
          <Clock className="h-4 w-4 text-slate-400" />
          <span>{row.original.duration_minutes} min</span>
        </div>
      ),
    },
    {
      accessorKey: 'invite_count',
      header: 'Students',
      cell: ({ row }) => (
        <div className="flex items-center gap-1.5 text-slate-600">
          <Users className="h-4 w-4 text-slate-400" />
          <span className="font-medium">{row.original.invite_count}</span>
        </div>
      ),
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <div className="text-right">
          <Button
            variant="ghost"
            size="icon"
            className="hover:bg-slate-100 text-slate-400 hover:text-slate-900"
            onClick={() => router.push(`/admin/dashboard/exams/${row.original.id}`)}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ], [router]);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">Exams</h1>
          <p className="text-slate-500 mt-1">Manage and monitor all your proctored examinations.</p>
        </div>
        <Button onClick={() => router.push('/admin/dashboard/exams/new')} className="gap-2">
          <Plus className="h-4 w-4" />
          Create Exam
        </Button>
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
