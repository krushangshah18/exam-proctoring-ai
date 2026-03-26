'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, AlertTriangle, ClipboardCheck, Loader2, MessageSquare, ArrowRight } from 'lucide-react';
import api from '@/lib/axios';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

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
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export default function AdminAppealsInboxPage() {
  const router = useRouter();
  const [appeals, setAppeals] = useState<PendingAppeal[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAppeals = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get('/admin/exams/pending-appeals');
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
    <div className="space-y-6 pb-10">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Button variant="outline" size="icon" onClick={() => router.push('/admin/dashboard')} className="h-10 w-10">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Appeal Inbox</h1>
            <p className="text-sm text-slate-500">Pending student appeals that need fast review.</p>
          </div>
        </div>
        <Button variant="outline" onClick={fetchAppeals}>Refresh</Button>
      </div>

      <Card className="border-amber-200 bg-amber-50/60 shadow-none">
        <CardContent className="pt-6 flex items-center gap-4">
          <div className="h-12 w-12 rounded-full bg-amber-100 flex items-center justify-center">
            <ClipboardCheck className="h-6 w-6 text-amber-700" />
          </div>
          <div>
            <p className="text-2xl font-bold text-slate-900">{appeals.length}</p>
            <p className="text-sm text-slate-600">Pending appeal{appeals.length !== 1 ? 's' : ''} waiting for review</p>
          </div>
        </CardContent>
      </Card>

      {loading ? (
        <div className="flex items-center justify-center p-20">
          <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
        </div>
      ) : appeals.length === 0 ? (
        <Card className="shadow-none border-slate-200">
          <CardContent className="py-16 text-center">
            <MessageSquare className="h-12 w-12 text-slate-300 mx-auto mb-3" />
            <p className="text-slate-600 font-medium">No pending appeals</p>
            <p className="text-sm text-slate-400 mt-1">This inbox updates automatically.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {appeals.map((appeal) => (
            <Card key={appeal.resume_request_id} className="shadow-none border-slate-200">
              <CardHeader className="pb-3">
                <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-3">
                  <div>
                    <CardTitle className="text-lg">{appeal.student_name}</CardTitle>
                    <CardDescription>{appeal.student_email}</CardDescription>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge className="bg-amber-100 text-amber-700 hover:bg-amber-100">Pending</Badge>
                    <Badge variant="outline" className="border-slate-200 text-slate-600">
                      {fmtDateTime(appeal.created_at)}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 md:grid-cols-2">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-wide text-slate-400 mb-1">Exam</p>
                    <p className="font-medium text-slate-900">{appeal.exam_title}</p>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <p className="text-xs uppercase tracking-wide text-slate-400 mb-1">Termination</p>
                    <p className="font-medium text-slate-900">{appeal.terminated_by || 'Late Join'}</p>
                    {appeal.terminated_reason && (
                      <p className="text-sm text-slate-500 mt-1">{appeal.terminated_reason}</p>
                    )}
                  </div>
                </div>

                <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-700 mt-0.5 shrink-0" />
                    <div>
                      <p className="text-xs uppercase tracking-wide text-amber-700 mb-1">Student Appeal</p>
                      <p className="text-sm text-slate-700 whitespace-pre-wrap">{appeal.reason || 'No reason provided.'}</p>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button onClick={() => router.push(`/admin/dashboard/exams/${appeal.exam_id}/monitor?tab=appeals`)}>
                    Review In Monitor <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
