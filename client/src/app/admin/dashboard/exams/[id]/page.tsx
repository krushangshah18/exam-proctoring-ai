"use client";

import { useEffect, useState } from 'react';
import { useRouter, useParams } from 'next/navigation';
import axios from 'axios';
import { toast } from 'sonner';
import api from '@/lib/axios';
import { fmtDate, fmtTime } from '@/lib/fmt-date';
import {
  ArrowLeft,
  Calendar,
  Clock,
  Users,
  Settings,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Loader2,
  Trash2,
  Edit,
  Activity
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
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
  invites: ExamInvite[];
}

export default function AdminExamDetailsPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;
  
  const [exam, setExam] = useState<ExamDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);

  useEffect(() => {
    if (examId) {
      fetchExamDetails();
    }
  }, [examId]);

  const fetchExamDetails = async () => {
    try {
      setLoading(true);
      const res = await api.get(`/admin/exams/${examId}`);
      setExam(res.data);
    } catch (error) {
      console.error("Failed to fetch exam details", error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch(status.toUpperCase()) {
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
    } catch (err) {
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

  const activeChecksCount = Object.values(exam.config).filter(Boolean).length;

  return (
    <div className="space-y-6 pb-12">
      <div className="flex items-center gap-4">
        <Button variant="outline" size="icon" onClick={() => router.back()} className="h-10 w-10 border-slate-200">
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-bold tracking-tight text-slate-900">{exam.title}</h1>
            <Badge className={getStatusColor(exam.status)} variant="outline">
              {exam.status}
            </Badge>
            <Badge variant="secondary" className="font-semibold text-[10px] uppercase">
              {exam.exam_mode}
            </Badge>
          </div>
          <p className="text-slate-500 mt-1 flex items-center gap-2">
            ID: <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded text-slate-600 font-mono">{exam.id}</code>
          </p>
        </div>
        <div className="ml-auto flex items-center gap-2">
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

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">Start Window</CardTitle>
            <Calendar className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-xl font-semibold text-slate-900">{fmtDate(exam.start_window)}</div>
            <p className="text-sm text-slate-500 mt-1 font-medium">{fmtTime(exam.start_window)}</p>
          </CardContent>
        </Card>
        
        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">End Window</CardTitle>
            <Calendar className="h-4 w-4 text-rose-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-xl font-semibold text-slate-900">{fmtDate(exam.end_window)}</div>
            <p className="text-sm text-slate-500 mt-1 font-medium">{fmtTime(exam.end_window)}</p>
          </CardContent>
        </Card>

        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="p-4 pb-2 border-b border-slate-100 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-medium text-slate-600">Duration</CardTitle>
            <Clock className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent className="p-4">
            <div className="text-2xl font-bold tracking-tight text-slate-900">{exam.duration_minutes}<span className="text-sm font-medium text-slate-500 ml-1">min</span></div>
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

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="shadow-none border-slate-200 bg-white">
          <CardHeader className="border-b border-slate-100 flex flex-row items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-50 flex items-center justify-center">
              <ShieldAlert className="h-5 w-5 text-indigo-500" />
            </div>
            <div>
              <CardTitle className="text-lg">Proctoring Configuration</CardTitle>
              <CardDescription>AI behavior and threshold rules</CardDescription>
            </div>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid grid-cols-2 gap-y-4 gap-x-8">
              <div className="space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Flag Threshold</span>
                <p className="text-lg font-medium text-slate-900">{exam.flag_threshold} violations</p>
              </div>
              <div className="space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Modules</span>
                <p className="text-lg font-medium text-indigo-600">{activeChecksCount} / {Object.keys(exam.config).length}</p>
              </div>
              <div className="space-y-1">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Late Policy</span>
                <p className="text-lg font-medium text-slate-900">{exam.late_join_policy}</p>
              </div>
            </div>
            
            <div className="mt-6 pt-6 border-t border-slate-100">
              <h4 className="text-sm font-medium text-slate-700 mb-4">Module Status Map</h4>
              <div className="flex flex-wrap gap-2">
                {Object.entries(exam.config).map(([key, enabled]) => (
                  <Badge key={key} variant="outline" className={`px-2 py-1 text-xs capitalize ${enabled ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-slate-50 text-slate-400 border-slate-200 line-through'}`}>
                    {key.replace('_', ' ')}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Invites Table Card */}
        <Card className="shadow-none border-slate-200 bg-white flex flex-col">
          <CardHeader className="border-b border-slate-100 flex flex-row items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-50 flex items-center justify-center">
              <Users className="h-5 w-5 text-amber-500" />
            </div>
            <div>
              <CardTitle className="text-lg">Student Roster</CardTitle>
              <CardDescription>Invited emails and their access status</CardDescription>
            </div>
          </CardHeader>
          <div className="overflow-auto flex-1 h-[300px]">
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-50/80 text-slate-500 sticky top-0 border-b border-slate-200">
                <tr>
                  <th className="px-4 py-3 font-medium">Email</th>
                  <th className="px-4 py-3 font-medium text-center">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {exam.invites.length === 0 ? (
                  <tr>
                    <td colSpan={2} className="px-4 py-8 text-center text-slate-500">No students invited yet.</td>
                  </tr>
                ) : (
                  exam.invites.map((invite) => (
                    <tr key={invite.id} className="hover:bg-slate-50">
                      <td className="px-4 py-3 font-medium text-slate-900">{invite.student_email}</td>
                      <td className="px-4 py-3 text-center">
                        {invite.used ? (
                          <Badge variant="outline" className="bg-emerald-50 text-emerald-700 border-emerald-200 pointer-events-none">
                            <CheckCircle2 className="h-3 w-3 mr-1" />
                            Accessed
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="bg-slate-50 text-slate-500 border-slate-200 pointer-events-none">
                            <Clock className="h-3 w-3 mr-1" />
                            Pending
                          </Badge>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
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
