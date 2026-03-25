"use client";

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { fmtDate, fmtTimeTZ } from '@/lib/fmt-date';
import {
  ArrowLeft,
  Calendar,
  Clock,
  Users,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Loader2,
  Trash2,
  Edit,
  Activity,
  Search,
  FileText,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';

interface ExamInvite {
  id: string;
  student_email: string;
  token: string;
  expires_at: string;
  used: boolean;
}

interface ExamDetail {
  id: string;
  title: string;
  exam_mode: string;
  status: string;
  start_window: string;
  end_window: string;
  duration_minutes: number;
  created_at: string;
  hard_join_deadline: string;
  flag_threshold: number;
  late_join_policy: string;
  allow_late_extension: boolean;
  max_late_minutes: number;
  config: Record<string, boolean>;
  detection_config: Record<string, boolean> | null;
  invites: ExamInvite[];
}

function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(iso) ? iso : iso + 'Z');
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AdminExamDetailsPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const [exam, setExam] = useState<ExamDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [rosterSearch, setRosterSearch] = useState('');

  useEffect(() => {
    if (examId) fetchExamDetails();
  }, [examId]);

  const fetchExamDetails = async () => {
    try {
      setLoading(true);
      const res = await api.get(`/admin/exams/${examId}`);
      setExam(res.data);
    } catch {
      toast.error('Failed to load exam details');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toUpperCase()) {
      case 'LIVE': return 'bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20 border-emerald-500/20';
      case 'DRAFT': return 'bg-slate-500/10 text-slate-500 hover:bg-slate-500/20 border-slate-500/20';
      case 'COMPLETED': return 'bg-blue-500/10 text-blue-500 hover:bg-blue-500/20 border-blue-500/20';
      default: return 'bg-slate-500/10 text-slate-500 border-slate-500/20';
    }
  };

  const handleDelete = async () => {
    try {
      await api.delete(`/admin/exams/${examId}`);
      toast.success('Exam deleted and notifications dispatched.');
      router.push('/admin/dashboard/exams');
    } catch {
      toast.error('Failed to delete exam.');
    }
  };

  if (loading || !exam) {
    return (
      <div className="flex flex-col items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400 mb-4" />
        <p className="text-slate-500">Loading Exam Data...</p>
      </div>
    );
  }

  const allModules = { ...(exam.config ?? {}), ...(exam.detection_config ?? {}) };
  const activeChecksCount = Object.values(allModules).filter(Boolean).length;
  const filteredInvites = exam.invites.filter(i =>
    i.student_email.toLowerCase().includes(rosterSearch.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="outline" size="icon" onClick={() => router.back()} className="h-10 w-10 border-slate-200">
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-3xl font-bold tracking-tight text-slate-900">{exam.title}</h1>
            <Badge className={getStatusColor(exam.status)} variant="outline">{exam.status}</Badge>
            <Badge variant="secondary" className="font-semibold text-[10px] uppercase">{exam.exam_mode}</Badge>
          </div>
          <p className="text-slate-500 mt-1 flex items-center gap-2">
            ID: <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded text-slate-600 font-mono">{exam.id}</code>
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2 flex-wrap">
          <Button variant="outline" className="gap-2 border-slate-200" onClick={() => router.push(`/admin/dashboard/exams/${examId}/reports`)}>
            <FileText className="h-4 w-4" /> Reports
          </Button>
          {(exam.status === 'LIVE' || exam.status === 'ENDED') && (
            <Button variant="outline" className="gap-2 border-indigo-200 text-indigo-700 hover:bg-indigo-50" onClick={() => router.push(`/admin/dashboard/exams/${examId}/monitor`)}>
              <Activity className="h-4 w-4" /> Monitor
            </Button>
          )}
          <Button variant="outline" className="gap-2" onClick={() => router.push(`/admin/dashboard/exams/${examId}/edit`)}>
            <Edit className="h-4 w-4" /> Edit
          </Button>
          <Button variant="destructive" className="gap-2 bg-rose-600" onClick={() => setIsDeleteDialogOpen(true)}>
            <Trash2 className="h-4 w-4" /> Delete
          </Button>
        </div>
      </div>

      {/* Top stat cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">Start Window</CardTitle>
            <Calendar className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-xl font-semibold text-slate-900">{fmtDate(exam.start_window)}</div>
            <p className="text-sm text-slate-500 mt-1 font-medium">{fmtTimeTZ(exam.start_window)}</p>
          </CardContent>
        </Card>

        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">End Window</CardTitle>
            <Calendar className="h-4 w-4 text-rose-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-xl font-semibold text-slate-900">{fmtDate(exam.end_window)}</div>
            <p className="text-sm text-slate-500 mt-1 font-medium">{fmtTimeTZ(exam.end_window)}</p>
          </CardContent>
        </Card>

        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">Duration</CardTitle>
            <Clock className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-2xl font-bold tracking-tight text-slate-900">
              {exam.duration_minutes}<span className="text-sm font-medium text-slate-500 ml-1">min</span>
            </div>
            <p className="text-sm text-slate-500 mt-1">Strict timer</p>
          </CardContent>
        </Card>

        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">Students Invited</CardTitle>
            <Users className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-2xl font-bold tracking-tight text-slate-900">{exam.invites.length}</div>
            <p className="text-sm text-slate-500 mt-1">{exam.invites.filter(i => i.used).length} accessed</p>
          </CardContent>
        </Card>
      </div>

      {/* Schedule & Policy */}
      <Card className="shadow-none border-slate-200 bg-white">
        <CardHeader className="border-b border-slate-100 flex flex-row items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center">
            <Info className="h-5 w-5 text-blue-500" />
          </div>
          <div>
            <CardTitle className="text-lg">Schedule & Policy</CardTitle>
            <CardDescription>Timing and access control settings</CardDescription>
          </div>
        </CardHeader>
        <CardContent className="p-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-8 gap-y-5">
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Hard Join Deadline</span>
              <p className="text-sm font-medium text-slate-900">{fmtDateTime(exam.hard_join_deadline)}</p>
            </div>
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Late Join Policy</span>
              <p className="text-sm font-medium text-slate-900 capitalize">{exam.late_join_policy.toLowerCase().replace('_', ' ')}</p>
            </div>
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Late Extension</span>
              <div className="flex items-center gap-1.5 mt-0.5">
                {exam.allow_late_extension ? (
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                ) : (
                  <XCircle className="h-4 w-4 text-slate-300" />
                )}
                <span className="text-sm font-medium text-slate-900">
                  {exam.allow_late_extension ? `Allowed (up to ${exam.max_late_minutes} min)` : 'Not allowed'}
                </span>
              </div>
            </div>
            <div className="space-y-1">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Created</span>
              <p className="text-sm font-medium text-slate-900">{fmtDateTime(exam.created_at)}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Proctoring Config */}
        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="border-b border-slate-100 flex flex-row items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-50 flex items-center justify-center">
              <ShieldAlert className="h-5 w-5 text-indigo-500" />
            </div>
            <div>
              <CardTitle className="text-lg">Proctoring Configuration</CardTitle>
              <CardDescription>AI behaviour and threshold rules</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="p-6 space-y-5">
            <div className="grid grid-cols-2 gap-y-4 gap-x-8">
              <div className="space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Flag Threshold</span>
                <p className="text-lg font-medium text-slate-900">{exam.flag_threshold} pts</p>
              </div>
              <div className="space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Modules</span>
                <p className="text-lg font-medium text-indigo-600">
                  {activeChecksCount} / {Object.keys(allModules).length}
                </p>
              </div>
            </div>

            {/* Browser-side checks */}
            {Object.keys(exam.config ?? {}).length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Browser Checks</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(exam.config).map(([key, enabled]) => (
                    <Badge key={key} variant="outline" className={`px-2 py-1 text-xs ${
                      enabled
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-slate-50 text-slate-400 border-slate-200 line-through'
                    }`}>
                      {key.replace(/_/g, ' ')}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* AI detection checks */}
            {exam.detection_config && Object.keys(exam.detection_config).length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">AI Detection</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(exam.detection_config).map(([key, enabled]) => (
                    <Badge key={key} variant="outline" className={`px-2 py-1 text-xs ${
                      enabled
                        ? 'bg-indigo-50 text-indigo-700 border-indigo-200'
                        : 'bg-slate-50 text-slate-400 border-slate-200 line-through'
                    }`}>
                      {key.replace(/_/g, ' ')}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Student Roster */}
        <Card className="shadow-none border-slate-200 bg-white flex flex-col">
          <CardHeader className="border-b border-slate-100 flex flex-row items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-50 flex items-center justify-center">
              <Users className="h-5 w-5 text-amber-500" />
            </div>
            <div className="flex-1 min-w-0">
              <CardTitle className="text-lg">Student Roster</CardTitle>
              <CardDescription>
                {exam.invites.filter(i => i.used).length} of {exam.invites.length} accessed
              </CardDescription>
            </div>
          </CardHeader>
          {/* Search */}
          <div className="px-4 pt-3 pb-2 border-b border-slate-100">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <Input
                placeholder="Search by email..."
                value={rosterSearch}
                onChange={e => setRosterSearch(e.target.value)}
                className="pl-8 h-8 text-sm border-slate-200"
              />
            </div>
          </div>
          <div className="overflow-auto flex-1 max-h-72">
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-50/80 text-slate-500 sticky top-0 border-b border-slate-200">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Email</th>
                  <th className="px-4 py-2.5 font-medium text-center w-24">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {filteredInvites.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="px-4 py-8 text-center text-slate-400 text-sm">
                      {rosterSearch ? 'No matching students.' : 'No students invited yet.'}
                    </td>
                  </tr>
                ) : (
                  filteredInvites.map((invite) => (
                    <tr key={invite.id} className="hover:bg-slate-50">
                      <td className="px-4 py-2.5 font-medium text-slate-900 text-sm">{invite.student_email}</td>
                      <td className="px-4 py-2.5 text-center">
                        {invite.used ? (
                          <Badge variant="outline" className="bg-emerald-50 text-emerald-700 border-emerald-200 pointer-events-none text-xs">
                            <CheckCircle2 className="h-3 w-3 mr-1" /> Accessed
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="bg-slate-50 text-slate-500 border-slate-200 pointer-events-none text-xs">
                            <Clock className="h-3 w-3 mr-1" /> Pending
                          </Badge>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {rosterSearch && (
            <div className="px-4 py-2 border-t border-slate-100 text-xs text-slate-400">
              {filteredInvites.length} of {exam.invites.length} shown
            </div>
          )}
        </Card>
      </div>

      <ConfirmDialog
        isOpen={isDeleteDialogOpen}
        onOpenChange={setIsDeleteDialogOpen}
        title="Delete Exam"
        description="Are you sure you want to completely delete this exam? This will securely delete all corresponding data, erase all student invites, and automatically dispatch a cancellation email to everyone previously invited. This action cannot be undone."
        onConfirm={handleDelete}
        confirmLabel="Yes, Delete Exam"
        cancelLabel="Cancel"
        variant="destructive"
      />
    </div>
  );
}
