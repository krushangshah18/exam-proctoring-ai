'use client';

import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import * as z from 'zod';
import { toast } from 'sonner';
import { 
  Check, 
  X, 
  Search, 
  MoreHorizontal, 
  Loader2,
  Building,
  Phone,
  Calendar,
  User
} from 'lucide-react';

import api from '@/lib/axios';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
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
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';

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
  const [applications, setApplications] = useState<AdminApplication[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
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

  const fetchApplications = async () => {
    try {
      const res = await api.get('/admin-applications');
      setApplications(res.data);
    } catch (error) {
      console.error('Failed to fetch applications', error);
      toast.error('Failed to load applications');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchApplications();
  }, []);

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
      console.error(error);
      toast.error(error.response?.data?.detail || 'Failed to process application');
    } finally {
      setProcessing(false);
    }
  };

  const openReviewDialog = (app: AdminApplication, action: 'approve' | 'reject') => {
    setSelectedApp(app);
    setReviewAction(action);
    setIsReviewOpen(true);
  };

  const resetReview = () => {
    setSelectedApp(null);
    setReviewAction(null);
    form.reset();
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'APPROVED':
        return <Badge className="bg-green-100 text-green-800 hover:bg-green-100 dark:bg-green-900/30 dark:text-green-400">Approved</Badge>;
      case 'REJECTED':
        return <Badge variant="destructive">Rejected</Badge>;
      default:
        return <Badge variant="secondary" className="bg-yellow-100 text-yellow-800 hover:bg-yellow-100 dark:bg-yellow-900/30 dark:text-yellow-400">Pending</Badge>;
    }
  };

  const filteredApplications = applications.filter(app => 
    app.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    app.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (app.organization && app.organization.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Admin Applications</h1>
          <p className="text-muted-foreground mt-2">
            Review and manage incoming teacher/admin applications.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>All Applications</CardTitle>
            <div className="relative w-64">
              <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search applications..."
                className="pl-8"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Applicant</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Applied On</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredApplications.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="h-24 text-center">
                    No applications found.
                  </TableCell>
                </TableRow>
              ) : (
                filteredApplications.map((app) => (
                  <TableRow key={app.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{app.full_name}</span>
                        <span className="text-xs text-muted-foreground">{app.email}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      {app.organization ? (
                        <div className="flex items-center gap-1">
                          <Building className="h-3 w-3 text-muted-foreground" />
                          <span>{app.organization}</span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground italic">--</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1 text-muted-foreground">
                        <Calendar className="h-3 w-3" />
                        <span>{new Date(app.created_at).toLocaleDateString()}</span>
                      </div>
                    </TableCell>
                    <TableCell>{getStatusBadge(app.status)}</TableCell>
                    <TableCell className="text-right">
                      {app.status === 'PENDING' ? (
                        <div className="flex justify-end gap-2">
                          <Button 
                            size="sm" 
                            variant="outline" 
                            className="text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-900/10"
                            onClick={() => openReviewDialog(app, 'approve')}
                          >
                            <Check className="h-4 w-4 mr-1" /> Approve
                          </Button>
                          <Button 
                            size="sm" 
                            variant="outline"
                            className="text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/10"
                            onClick={() => openReviewDialog(app, 'reject')}
                          >
                            <X className="h-4 w-4 mr-1" /> Reject
                          </Button>
                        </div>
                      ) : (
                        <div className="flex justify-end">
                            <Button variant="ghost" size="sm" onClick={() => {
                                setSelectedApp(app);
                                setIsReviewOpen(true);
                                setReviewAction(null); // Just viewing
                            }}>
                                View Details
                            </Button>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

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
                        {/* Details... */}
                        <div>
                            <span className="text-muted-foreground block mb-1">Full Name</span>
                            <div className="flex items-center gap-2 font-medium">
                                <User className="h-4 w-4" /> {selectedApp.full_name}
                            </div>
                        </div>
                        <div>
                            <span className="text-muted-foreground block mb-1">Applying For</span>
                            <Badge variant="outline">Admin / Teacher</Badge>
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
                            <div className="bg-muted p-3 rounded-md text-sm italic">
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
