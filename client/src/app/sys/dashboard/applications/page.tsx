'use client';

import { useEffect, useState, useMemo } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { toast } from 'sonner';
import { 
  Check, 
  X, 
  Loader2,
  Building,
  Calendar,
  User,
  MoreHorizontal
} from 'lucide-react';
import { fmtDate } from "@/lib/fmt-date";

import api from '@/lib/axios';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';

// New Shared Components
import { DataTable } from '@/components/common/DataTable';
import { SearchInput } from '@/components/common/SearchInput';
import { StatusBadge } from '@/components/common/StatusBadge';
import { Breadcrumbs } from '@/components/common/Breadcrumbs';
import { useTableURLState } from '@/hooks/useTableURLState';

// React Table
import { ColumnDef, PaginationState, SortingState } from "@tanstack/react-table";

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

const reviewSchema = z.object({
  review_note: z.string().optional(),
});

type ReviewFormValues = z.infer<typeof reviewSchema>;

export default function ApplicationsPage() {
  const { 
    page, size, search, sortBy, sortOrder, 
    setPage, setPageSize, setSearch, setSorting, clearSorting 
  } = useTableURLState();

  const [applications, setApplications] = useState<AdminApplication[]>([]);
  const [totalItems, setTotalItems] = useState(0);
  const [pageCount, setPageCount] = useState(0);
  
  const [loading, setLoading] = useState(true);
  
  const [selectedApp, setSelectedApp] = useState<AdminApplication | null>(null);
  const [isReviewOpen, setIsReviewOpen] = useState(false);
  const [reviewAction, setReviewAction] = useState<'approve' | 'reject' | null>(null);
  const [processing, setProcessing] = useState(false);

  const form = useForm<ReviewFormValues>({
    resolver: zodResolver(reviewSchema),
    defaultValues: {
      review_note: '',
    },
  });

  const [searchTrigger, setSearchTrigger] = useState(0);

  const fetchApplications = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin-applications', {
        params: {
          page,
          size,
          search: search || undefined,
          sort_by: sortBy || undefined,
          sort_order: sortOrder || 'desc'
        }
      });
      setApplications(res.data.items);
      setTotalItems(res.data.total);
      setPageCount(res.data.pages);
    } catch (error) {
      console.error('Failed to fetch applications', error);
      toast.error('Failed to load applications');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApplications();
  }, [page, size, search, sortBy, sortOrder, searchTrigger]);

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
      fetchApplications(); // Refresh data
    } catch (error: any) {
      console.error(error);
      toast.error(error.response?.data?.detail || 'Failed to process application');
    } finally {
      setProcessing(false);
    }
  };

  const openReviewDialog = (app: AdminApplication, action: 'approve' | 'reject' | null) => {
    setSelectedApp(app);
    setReviewAction(action);
    setIsReviewOpen(true);
  };

  const resetReview = () => {
    setSelectedApp(null);
    setReviewAction(null);
    form.reset();
  };

  // React Table State Mappers - wrap in useMemo to avoid reference churn
  const pagination: PaginationState = useMemo(() => ({
    pageIndex: page - 1,
    pageSize: size,
  }), [page, size]);

  const handlePaginationChange = (updater: any) => {
    const newPagination =
      typeof updater === 'function' ? updater(pagination) : updater;

    const newPage = newPagination.pageIndex + 1;
    const newSize = newPagination.pageSize;

    if (newSize !== size) {
      setPageSize(newSize);
      return; 
    }

    if (newPage !== page) {
      setPage(newPage);
    }
  };

  const sortingState: SortingState = useMemo(() => {
    return sortBy ? [{ id: sortBy, desc: sortOrder === 'desc' }] : [];
  }, [sortBy, sortOrder]);

  const handleSortingChange = (updater: any) => {
    const newSorting = typeof updater === 'function' ? updater(sortingState) : updater;
    if (newSorting.length > 0) {
      setSorting(newSorting[0].id, newSorting[0].desc ? 'desc' : 'asc');
    } else {
      clearSorting();
    }
  };

  const columns = useMemo<ColumnDef<AdminApplication>[]>(() => [
    {
      accessorKey: 'full_name',
      header: 'Applicant',
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.original.full_name}</span>
          <span className="text-xs text-muted-foreground">{row.original.email}</span>
        </div>
      ),
    },
    {
      accessorKey: 'organization',
      header: 'Organization',
      cell: ({ row }) => (
        row.original.organization ? (
          <div className="flex items-center gap-1">
            <Building className="h-3 w-3 text-muted-foreground" />
            <span>{row.original.organization}</span>
          </div>
        ) : (
          <span className="text-muted-foreground italic">--</span>
        )
      )
    },
    {
      accessorKey: 'created_at',
      header: 'Applied On',
      cell: ({ row }) => {
        try {
          return (
            <div className="flex items-center gap-1 text-muted-foreground whitespace-nowrap">
              <Calendar className="h-3 w-3" />
              <span>{fmtDate(row.original.created_at)}</span>
            </div>
          );
        } catch {
          return <span>Invalid Date</span>;
        }
      }
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: ({ row }) => <StatusBadge status={row.original.status} />
    },
    {
      id: 'actions',
      header: 'Actions',
      enableSorting: false,
      cell: ({ row }) => {
        const app = row.original;
        
        if (app.status === 'PENDING') {
          return (
            <div className="flex justify-start gap-2">
              <Button 
                size="sm" 
                variant="outline" 
                className="text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-900/10"
                onClick={(e) => {
                  e.stopPropagation();
                  openReviewDialog(app, 'approve');
                }}
              >
                <Check className="h-4 w-4 mr-1" /> Approve
              </Button>
              <Button 
                size="sm" 
                variant="outline"
                className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/10"
                onClick={(e) => {
                  e.stopPropagation();
                  openReviewDialog(app, 'reject');
                }}
              >
                <X className="h-4 w-4 mr-1" /> Reject
              </Button>
            </div>
          );
        }
        
        return (
          <Button 
            variant="ghost" 
            size="sm" 
            onClick={(e) => {
              e.stopPropagation();
              openReviewDialog(app, null); // Just viewing
            }}
          >
            View Details
          </Button>
        );
      }
    }
  ], []);

  return (
    <div className="space-y-6 p-6">
      <Breadcrumbs />
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Admin Applications</h1>
          <p className="text-muted-foreground mt-2">
            Review and manage incoming teacher/admin applications.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader className="pb-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <CardTitle>All Applications</CardTitle>
            <SearchInput 
              initialValue={search} 
              onSearch={setSearch} 
              placeholder="Search by name, email, or org..."
              isLoading={loading}
              debounceMs={600}
            />
          </div>
        </CardHeader>
        <CardContent>
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
        </CardContent>
      </Card>

      {/* Review Dialog */}
      <Dialog open={isReviewOpen} onOpenChange={(open) => {
          if (!open) resetReview();
          setIsReviewOpen(open);
      }}>
        <DialogContent className="sm:max-w-[500px]">
          <Form {...form}>
            <DialogHeader>
                <DialogTitle>
                    {reviewAction ? (reviewAction === 'approve' ? 'Approve Application' : 'Reject Application') : 'Application Details'}
                </DialogTitle>
                <DialogDescription>
                    Review details for {selectedApp?.full_name}
                </DialogDescription>
            </DialogHeader>

            {selectedApp && (
                <div className="grid gap-4 py-4">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                            <span className="text-muted-foreground block mb-1">Full Name</span>
                            <div className="flex items-center gap-2 font-medium">
                                <User className="h-4 w-4" /> {selectedApp.full_name}
                            </div>
                        </div>
                        <div>
                            <span className="text-muted-foreground block mb-1">Applying For</span>
                            <StatusBadge status="ADMIN" className="bg-purple-100 text-purple-800 border-purple-200" />
                        </div>
                        <div>
                            <span className="text-muted-foreground block mb-1">Organization</span>
                            <div className="text-foreground">{selectedApp.organization || '--'}</div>
                        </div>
                        <div>
                            <span className="text-muted-foreground block mb-1">Contact</span>
                            <div className="text-foreground">{selectedApp.contact_number || '--'}</div>
                        </div>
                    </div>

                    <div>
                        <span className="text-muted-foreground block mb-2 text-sm">Reason for Application</span>
                        <div className="bg-muted p-3 rounded-md text-sm whitespace-pre-wrap">
                            {selectedApp.reason}
                        </div>
                    </div>

                    {reviewAction && (
                        <div className="space-y-4 pt-4 border-t">
                            <div className={`p-3 rounded-md text-sm ${
                                reviewAction === 'approve' 
                                ? 'bg-blue-50 text-blue-700 dark:bg-blue-900/20 dark:text-blue-300'
                                : 'bg-red-50 text-red-700 dark:bg-red-900/20 dark:text-red-300'
                            }`}>
                                {reviewAction === 'approve' 
                                ? 'Approving this application will create a new Admin account and email credentials to the user.' 
                                : 'Rejecting this application will notify the user via email.'}
                            </div>

                            <div className="space-y-2">
                                <FormField
                                    control={form.control}
                                    name="review_note"
                                    render={({ field }) => (
                                        <FormItem>
                                            <FormLabel>Review Note (Optional)</FormLabel>
                                            <FormControl>
                                                <Textarea 
                                                    placeholder="Add an internal note or reason..." 
                                                    {...field}
                                                />
                                            </FormControl>
                                            <FormMessage />
                                        </FormItem>
                                    )}
                                />
                            </div>
                        </div>
                    )}
                    
                    {!reviewAction && selectedApp.review_note && (
                        <div>
                            <span className="text-muted-foreground block mb-2 text-sm">Review Note</span>
                            <div className="bg-muted p-3 rounded-md text-sm italic border-l-4 border-primary/50">
                                "{selectedApp.review_note}"
                            </div>
                        </div>
                    )}
                </div>
            )}

            <DialogFooter>
                <Button variant="outline" onClick={() => setIsReviewOpen(false)} disabled={processing}>
                {reviewAction ? 'Cancel' : 'Close'}
                </Button>
                {reviewAction && (
                    <Button 
                        variant={reviewAction === 'approve' ? 'default' : 'destructive'}
                        onClick={form.handleSubmit(handleReview)}
                        disabled={processing}
                    >
                        {processing && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                        {reviewAction === 'approve' ? 'Confirm Approval' : 'Confirm Rejection'}
                    </Button>
                )}
            </DialogFooter>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
