"use client";

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';
import { fmtDate, fmtTimeTZ } from '@/lib/fmt-date';
import { 
  Plus, 
  Search, 
  Calendar, 
  Clock, 
  Users,
  MoreVertical,
  ChevronRight,
  Loader2
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

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

  const filteredExams = exams.filter(e => e.title.toLowerCase().includes(search.toLowerCase()));

  const getStatusColor = (status: string) => {
    switch(status.toUpperCase()) {
      case 'LIVE': return 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20';
      case 'DRAFT': return 'bg-slate-500/10 text-slate-500 hover:bg-slate-500/20';
      case 'COMPLETED': return 'bg-blue-500/10 text-blue-500 hover:bg-blue-500/20';
      default: return 'bg-slate-500/10 text-slate-500';
    }
  };

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
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
          <Input 
            placeholder="Search exams by title..." 
            className="pl-9 bg-white"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <Card className="border-slate-200 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="bg-slate-50/80 text-slate-500 border-b border-slate-200">
              <tr>
                <th className="px-6 py-4 font-medium">Exam Details</th>
                <th className="px-6 py-4 font-medium hidden md:table-cell">Schedule</th>
                <th className="px-6 py-4 font-medium hidden sm:table-cell">Duration</th>
                <th className="px-6 py-4 font-medium">Students</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 bg-white">
              {loading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center h-48">
                    <Loader2 className="h-6 w-6 animate-spin text-slate-400 mx-auto mb-2" />
                    <p className="text-slate-500">Loading exams...</p>
                  </td>
                </tr>
              ) : filteredExams.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center h-48">
                    <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-slate-100 mb-4">
                      <Search className="h-6 w-6 text-slate-400" />
                    </div>
                    <p className="text-slate-900 font-medium">No exams found</p>
                    <p className="text-slate-500 mt-1">Try adjusting your search or create a new exam.</p>
                  </td>
                </tr>
              ) : (
                filteredExams.map((exam) => (
                  <tr key={exam.id} className="hover:bg-slate-50/50 transition-colors group cursor-pointer" onClick={() => router.push(`/admin/dashboard/exams/${exam.id}`)}>
                    <td className="px-6 py-4">
                      <div className="flex flex-col gap-1">
                        <span className="font-semibold text-slate-900">{exam.title}</span>
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary" className="text-[10px] px-1.5 py-0 font-medium">
                            {exam.exam_mode}
                          </Badge>
                          <Badge className={getStatusColor(exam.status)} variant="outline">
                            {exam.status}
                          </Badge>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 hidden md:table-cell text-slate-600">
                      <div className="flex items-center gap-2 mb-1">
                        <Calendar className="h-3.5 w-3.5 text-slate-400" />
                        <span>{fmtDate(exam.start_window)}, {fmtTimeTZ(exam.start_window)}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 hidden sm:table-cell">
                      <div className="flex items-center gap-1.5 text-slate-600">
                        <Clock className="h-4 w-4 text-slate-400" />
                        <span>{exam.duration_minutes} min</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-1.5 text-slate-600">
                        <Users className="h-4 w-4 text-slate-400" />
                        <span className="font-medium">{exam.invite_count}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <Button variant="ghost" size="icon" className="hover:bg-slate-100 text-slate-400 hover:text-slate-900" onClick={(e) => { e.stopPropagation(); router.push(`/admin/dashboard/exams/${exam.id}`); }}>
                        <ChevronRight className="h-4 w-4" />
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
