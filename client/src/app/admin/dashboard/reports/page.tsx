'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  FileText, Loader2, RefreshCw, Calendar, Clock, Users,
  ChevronRight, ShieldAlert, Search,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import api from '@/lib/axios';

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

const STATUS_STYLES: Record<string, string> = {
  LIVE: 'bg-emerald-500/10 text-emerald-600 border-emerald-200',
  DRAFT: 'bg-slate-100 text-slate-500 border-slate-200',
  COMPLETED: 'bg-blue-500/10 text-blue-600 border-blue-200',
  SCHEDULED: 'bg-indigo-500/10 text-indigo-600 border-indigo-200',
  ENDED: 'bg-slate-100 text-slate-500 border-slate-200',
  CANCELLED: 'bg-rose-100 text-rose-600 border-rose-200',
};

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AdminReportsPage() {
  const router = useRouter();
  const [exams, setExams] = useState<ExamSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const fetchExams = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin/exams');
      setExams(res.data);
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchExams(); }, [fetchExams]);

  const filtered = exams.filter(e =>
    e.title.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900">Reports</h1>
          <p className="text-slate-500 mt-1">View session reports for each exam.</p>
        </div>
        <Button variant="outline" size="sm" onClick={fetchExams} className="gap-2 border-slate-200">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
        <Input
          placeholder="Search exams..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="pl-9 border-slate-200"
        />
      </div>

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-slate-300" />
        </div>
      ) : filtered.length === 0 ? (
        <Card className="border-slate-200 shadow-none">
          <CardContent className="py-16 text-center">
            <FileText className="h-12 w-12 text-slate-200 mx-auto mb-3" />
            <p className="text-slate-500">{search ? 'No exams match your search.' : 'No exams found.'}</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {filtered.map((exam) => (
            <Card
              key={exam.id}
              className="border-slate-200 shadow-none hover:shadow-sm transition-shadow cursor-pointer"
              onClick={() => router.push(`/admin/dashboard/exams/${exam.id}/reports`)}
            >
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  <div className="h-10 w-10 rounded-lg bg-indigo-50 flex items-center justify-center shrink-0">
                    <FileText className="h-5 w-5 text-indigo-500" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-0.5">
                      <p className="font-semibold text-slate-900 truncate">{exam.title}</p>
                      <Badge variant="outline" className={`text-xs ${STATUS_STYLES[exam.status] ?? 'bg-slate-100 text-slate-500'}`}>
                        {exam.status}
                      </Badge>
                      <Badge variant="secondary" className="text-[10px] px-1.5 py-0 font-medium">
                        {exam.exam_mode}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-slate-400 flex-wrap">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {fmtDate(exam.start_window)}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {exam.duration_minutes} min
                      </span>
                      <span className="flex items-center gap-1">
                        <Users className="h-3 w-3" />
                        {exam.invite_count} student{exam.invite_count !== 1 ? 's' : ''}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs text-indigo-600 font-medium hidden sm:block">View Reports</span>
                    <ChevronRight className="h-4 w-4 text-slate-400" />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
