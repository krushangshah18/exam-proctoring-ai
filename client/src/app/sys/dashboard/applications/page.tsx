'use client';

import { useEffect, useState, useMemo } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { toast } from 'sonner';
import { Check, X, Loader2, Building, Calendar, User } from 'lucide-react';
import { fmtDate } from '@/lib/fmt-date';
import api from '@/lib/axios';
import {
  Form, FormControl, FormField, FormItem, FormLabel, FormMessage,
} from '@/components/ui/form';
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { DataTable } from '@/components/common/DataTable';
import { SearchInput } from '@/components/common/SearchInput';
import { StatusBadge } from '@/components/common/StatusBadge';
import { Breadcrumbs } from '@/components/common/Breadcrumbs';
import { useTableURLState } from '@/hooks/useTableURLState';
import { ColumnDef, PaginationState, SortingState } from '@tanstack/react-table';

interface AdminApplication {
  id: string;
  full_name: string;
  email: string;
  organization: string | null;
  contact_number: string | null;
  reason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  created_at: string;
  reviewed_by: string | null;
  review_note: string | null;
}

const reviewSchema = z.object({ review_note: z.string().optional() });
type ReviewFormValues = z.infer<typeof reviewSchema>;

export default function ApplicationsPage() {
  const { page, size, search, sortBy, sortOrder, setPage, setPageSize, setSearch, setSorting, clearSorting } = useTableURLState();

  const [applications, setApplications] = useState<AdminApplication[]>([]);
  const [totalItems, setTotalItems]     = useState(0);
  const [pageCount, setPageCount]       = useState(0);
  const [loading, setLoading]           = useState(true);
  const [selectedApp, setSelectedApp]   = useState<AdminApplication | null>(null);
  const [isReviewOpen, setIsReviewOpen] = useState(false);
  const [reviewAction, setReviewAction] = useState<'approve' | 'reject' | null>(null);
  const [processing, setProcessing]     = useState(false);
  const [searchTrigger, setSearchTrigger] = useState(0);

  const form = useForm<ReviewFormValues>({
    resolver: zodResolver(reviewSchema),
    defaultValues: { review_note: '' },
  });

  const fetchApplications = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin-applications', {
        params: { page, size, search: search || undefined, sort_by: sortBy || undefined, sort_order: sortOrder || 'desc' },
      });
      setApplications(res.data.items);
      setTotalItems(res.data.total);
      setPageCount(res.data.pages);
    } catch { toast.error('Failed to load applications'); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchApplications(); }, [page, size, search, sortBy, sortOrder, searchTrigger]);

  const handleReview = async (data: ReviewFormValues) => {
    if (!selectedApp || !reviewAction) return;
    setProcessing(true);
    try {
      await api.post(`/admin-applications/${selectedApp.id}/review`, {
        approve: reviewAction === 'approve',
        review_note: data.review_note,
      });
      toast.success(`Application ${reviewAction === 'approve' ? 'approved' : 'rejected'} successfully`);
      setIsReviewOpen(false);
      resetReview();
      fetchApplications();
    } catch (error: any) {
      const detail = error.response?.data?.detail;
      toast.error(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail[0]?.msg : 'Failed to process application');
    } finally { setProcessing(false); }
  };

  const openReviewDialog = (app: AdminApplication, action: 'approve' | 'reject' | null) => {
    setSelectedApp(app); setReviewAction(action); setIsReviewOpen(true);
  };

  const resetReview = () => { setSelectedApp(null); setReviewAction(null); form.reset(); };

  const pagination: PaginationState = useMemo(() => ({ pageIndex: page - 1, pageSize: size }), [page, size]);

  const handlePaginationChange = (updater: any) => {
    const np = typeof updater === 'function' ? updater(pagination) : updater;
    if (np.pageSize !== size) { setPageSize(np.pageSize); return; }
    if (np.pageIndex + 1 !== page) setPage(np.pageIndex + 1);
  };

  const sortingState: SortingState = useMemo(() =>
    sortBy ? [{ id: sortBy, desc: sortOrder === 'desc' }] : [], [sortBy, sortOrder]);

  const handleSortingChange = (updater: any) => {
    const ns = typeof updater === 'function' ? updater(sortingState) : updater;
    if (ns.length > 0) setSorting(ns[0].id, ns[0].desc ? 'desc' : 'asc');
    else clearSorting();
  };

  const columns = useMemo<ColumnDef<AdminApplication>[]>(() => [
    {
      accessorKey: 'full_name',
      header: 'Applicant',
      cell: ({ row }) => (
        <div>
          <p className="font-semibold text-sm" style={{ color: '#0F172A' }}>{row.original.full_name}</p>
          <p className="text-xs mt-0.5" style={{ color: '#94A3B8' }}>{row.original.email}</p>
        </div>
      ),
    },
    {
      accessorKey: 'organization',
      header: 'Organization',
      cell: ({ row }) => row.original.organization ? (
        <span className="flex items-center gap-1.5 text-sm" style={{ color: '#475569' }}>
          <Building className="h-3.5 w-3.5" style={{ color: '#94A3B8' }} />
          {row.original.organization}
        </span>
      ) : <span style={{ color: '#CBD5E1' }}>—</span>,
    },
    {
      accessorKey: 'created_at',
      header: 'Applied',
      cell: ({ row }) => (
        <span className="flex items-center gap-1.5 text-sm" style={{ color: '#475569' }}>
          <Calendar className="h-3.5 w-3.5" style={{ color: '#94A3B8' }} />
          {fmtDate(row.original.created_at)}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => <StatusBadge status={row.original.status} />,
    },
    {
      id: 'actions',
      header: 'Actions',
      enableSorting: false,
      cell: ({ row }) => {
        const app = row.original;
        if (app.status === 'PENDING') {
          return (
            <div className="flex gap-2">
              <button
                onClick={e => { e.stopPropagation(); openReviewDialog(app, 'approve'); }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150"
                style={{ background: '#ECFDF5', color: '#15803D', borderColor: '#BBF7D0' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#DCFCE7'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#ECFDF5'; }}
              >
                <Check className="h-3.5 w-3.5" /> Approve
              </button>
              <button
                onClick={e => { e.stopPropagation(); openReviewDialog(app, 'reject'); }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-150"
                style={{ background: '#FFF1F2', color: '#BE123C', borderColor: '#FECDD3' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = '#FFE4E6'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = '#FFF1F2'; }}
              >
                <X className="h-3.5 w-3.5" /> Reject
              </button>
            </div>
          );
        }
        return (
          <button
            onClick={e => { e.stopPropagation(); openReviewDialog(app, null); }}
            className="text-xs font-medium px-3 py-1.5 rounded-lg border transition-all duration-150"
            style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
          >
            View Details
          </button>
        );
      },
    },
  ], []);

  return (
    <div className="space-y-6 max-w-6xl pb-12">
      <Breadcrumbs />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: '#0F172A', letterSpacing: '-0.025em' }}>
            Admin Applications
          </h1>
          <p className="text-sm mt-1" style={{ color: '#94A3B8' }}>
            Review and manage incoming teacher and admin account requests.
          </p>
        </div>
      </div>

      {/* Table card */}
      <div className="bg-white rounded-xl border overflow-hidden"
        style={{ borderColor: '#E2E8F0', boxShadow: '0 1px 3px rgba(15,23,42,0.04)' }}>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 px-5 py-4"
          style={{ borderBottom: '1px solid #F1F5F9' }}>
          <p className="text-sm font-semibold" style={{ color: '#0F172A' }}>All Applications</p>
          <SearchInput
            initialValue={search}
            onSearch={setSearch}
            placeholder="Search by name, email, or org…"
            isLoading={loading}
            debounceMs={600}
          />
        </div>
        <div className="p-5">
          <DataTable
            columns={columns}
            data={applications}
            pageCount={pageCount}
            totalItems={totalItems}
            isLoading={loading}
            pagination={pagination}
            onPaginationChange={handlePaginationChange}
            sorting={sortingState}
            onSortingChange={handleSortingChange}
          />
        </div>
      </div>

      {/* Review Dialog */}
      <Dialog open={isReviewOpen} onOpenChange={open => { if (!open) resetReview(); setIsReviewOpen(open); }}>
        <DialogContent className="sm:max-w-[500px]">
          <Form {...form}>
            <DialogHeader>
              <DialogTitle>
                {reviewAction ? (reviewAction === 'approve' ? 'Approve Application' : 'Reject Application') : 'Application Details'}
              </DialogTitle>
              <DialogDescription>Review details for {selectedApp?.full_name}</DialogDescription>
            </DialogHeader>

            {selectedApp && (
              <div className="space-y-4 py-2">
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: 'Full Name',     value: <span className="flex items-center gap-1.5 font-medium" style={{ color: '#0F172A' }}><User className="h-3.5 w-3.5" style={{ color: '#94A3B8' }} />{selectedApp.full_name}</span> },
                    { label: 'Organization',  value: <span style={{ color: '#475569' }}>{selectedApp.organization || '—'}</span> },
                    { label: 'Contact',       value: <span style={{ color: '#475569' }}>{selectedApp.contact_number || '—'}</span> },
                    { label: 'Applying For',  value: <span className="px-2 py-0.5 rounded-md text-xs font-semibold border" style={{ background: '#F5F3FF', color: '#7C3AED', borderColor: '#DDD6FE' }}>Admin Account</span> },
                  ].map(({ label, value }) => (
                    <div key={label}>
                      <p className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: '#94A3B8' }}>{label}</p>
                      <div className="text-sm">{value}</div>
                    </div>
                  ))}
                </div>

                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: '#94A3B8' }}>Reason</p>
                  <div className="p-3 rounded-lg text-sm leading-relaxed"
                    style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', color: '#475569' }}>
                    {selectedApp.reason}
                  </div>
                </div>

                {reviewAction && (
                  <div className="space-y-3 pt-3" style={{ borderTop: '1px solid #F1F5F9' }}>
                    <div className="p-3 rounded-lg text-sm"
                      style={{
                        background: reviewAction === 'approve' ? '#EFF6FF' : '#FFF1F2',
                        color: reviewAction === 'approve' ? '#1D4ED8' : '#BE123C',
                        border: `1px solid ${reviewAction === 'approve' ? '#BFDBFE' : '#FECDD3'}`,
                      }}>
                      {reviewAction === 'approve'
                        ? 'Approving creates a new Admin account and emails credentials to the user.'
                        : 'Rejecting this application will notify the user via email.'}
                    </div>
                    <FormField
                      control={form.control}
                      name="review_note"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-sm font-medium" style={{ color: '#475569' }}>Review Note (Optional)</FormLabel>
                          <FormControl>
                            <Textarea placeholder="Add an internal note or reason…" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                )}

                {!reviewAction && selectedApp.review_note && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: '#94A3B8' }}>Review Note</p>
                    <div className="p-3 rounded-lg text-sm italic" style={{ background: '#F8FAFC', border: '1px solid #E2E8F0', borderLeft: '3px solid #22577A', color: '#475569' }}>
                      "{selectedApp.review_note}"
                    </div>
                  </div>
                )}
              </div>
            )}

            <DialogFooter>
              <button
                onClick={() => setIsReviewOpen(false)}
                disabled={processing}
                className="px-4 py-2 rounded-lg text-sm font-medium border transition-all duration-150"
                style={{ borderColor: '#E2E8F0', color: '#475569', background: '#fff' }}
              >
                {reviewAction ? 'Cancel' : 'Close'}
              </button>
              {reviewAction && (
                <button
                  onClick={form.handleSubmit(handleReview)}
                  disabled={processing}
                  className="px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all duration-150"
                  style={{ background: reviewAction === 'approve' ? '#22577A' : '#DC2626' }}
                >
                  {processing && <Loader2 className="inline h-4 w-4 animate-spin mr-2" />}
                  {reviewAction === 'approve' ? 'Confirm Approval' : 'Confirm Rejection'}
                </button>
              )}
            </DialogFooter>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
