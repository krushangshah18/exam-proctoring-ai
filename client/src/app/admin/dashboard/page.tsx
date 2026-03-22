'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  PlusCircle, 
  Users, 
  ClipboardCheck, 
  CalendarClock,
  ArrowRight,
  TrendingUp,
  Activity,
  FileText,
  Settings
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';

export default function AdminDashboard() {
  const router = useRouter();
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const res = await api.get('/auth/me');
      setUser(res.data);
    } catch (error) {
      console.error('Failed to fetch user profile', error);
    }
  };

  const metrics = [
    {
      title: "Active Exams",
      value: "4",
      icon: Activity,
      description: "2 ongoing right now",
      color: "text-blue-600",
      bg: "bg-blue-100 dark:bg-blue-900/30",
    },
    {
      title: "Students Evaluated",
      value: "1,248",
      icon: Users,
      description: "+12% from last month",
      color: "text-green-600",
      bg: "bg-green-100 dark:bg-green-900/30",
    },
    {
      title: "Pending Reports",
      value: "12",
      icon: ClipboardCheck,
      description: "Requires manual review",
      color: "text-amber-600",
      bg: "bg-amber-100 dark:bg-amber-900/30",
    },
    {
      title: "Upcoming Exams",
      value: "7",
      icon: CalendarClock,
      description: "Scheduled for this week",
      color: "text-purple-600",
      bg: "bg-purple-100 dark:bg-purple-900/30",
    }
  ];

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      
      {/* Welcome Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-indigo-500 rounded-2xl to-purple-600 p-8 text-white shadow-lg">
        <div>
          <h1 className="text-3xl font-bold mb-2">
            Welcome back, {user?.full_name?.split(' ')[0] || 'Admin'}!
          </h1>
          <p className="text-indigo-100 max-w-xl">
            Here's what's happening in your examination environments today. You have 12 pending violation reports that require your manual review.
          </p>
        </div>
        <Button 
          onClick={() => router.push('/admin/dashboard/exams/new')}
          className="bg-white text-indigo-600 hover:bg-indigo-50 shadow-md font-semibold px-6 py-6"
        >
          <PlusCircle className="mr-2 h-5 w-5" />
          Create New Exam
        </Button>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metrics.map((metric, i) => (
          <Card key={i} className="border-none shadow-md hover:shadow-lg transition-shadow">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                {metric.title}
              </CardTitle>
              <div className={`p-2 rounded-full ${metric.bg}`}>
                <metric.icon className={`h-4 w-4 ${metric.color}`} />
              </div>
            </CardHeader>
            <CardContent>
              <div className="text-3xl font-bold">{metric.value}</div>
              <p className="text-xs text-muted-foreground mt-1 flex items-center">
                {metric.title === "Students Evaluated" && <TrendingUp className="h-3 w-3 mr-1 text-green-500" />}
                {metric.description}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Recent Exams List */}
        <Card className="lg:col-span-2 shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between border-b pb-4">
            <div>
              <CardTitle>Recent Exams</CardTitle>
              <CardDescription>Latest examination sessions across all courses</CardDescription>
            </div>
            <Button variant="ghost" className="text-indigo-600" onClick={() => router.push('/admin/dashboard/exams')}>
              View All <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y">
              {[1, 2, 3].map((_, i) => (
                <div key={i} className="flex items-center justify-between p-6 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
                  <div className="flex items-center gap-4">
                    <div className="h-10 w-10 rounded-lg bg-indigo-100 dark:bg-indigo-900/40 flex items-center justify-center">
                      <FileText className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
                    </div>
                    <div>
                      <h4 className="font-semibold">Advanced Machine Learning (CS401)</h4>
                      <p className="text-sm text-muted-foreground block md:hidden">Today at 10:00 AM</p>
                    </div>
                  </div>
                  <div className="hidden md:block text-right">
                    <p className="text-sm font-medium">Today at 10:00 AM</p>
                    <p className="text-xs text-muted-foreground">Duration: 120 mins</p>
                  </div>
                  <Button variant="outline" size="sm">Manage</Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Action Panel */}
        <Card className="shadow-sm">
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Shortcut to common admin tasks</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Button variant="outline" className="w-full justify-start h-12" onClick={() => router.push('/admin/dashboard/reports')}>
              <ClipboardCheck className="mr-3 h-5 w-5 text-amber-500" />
              <div className="flex flex-col items-start">
                <span className="font-medium">Review Flags</span>
                <span className="text-xs text-muted-foreground font-normal">12 unattended reports</span>
              </div>
            </Button>
            
            <Button variant="outline" className="w-full justify-start h-12" onClick={() => router.push('/admin/dashboard/settings')}>
              <Settings className="mr-3 h-5 w-5 text-gray-500" />
              <span className="font-medium">Proctoring Settings</span>
            </Button>
            
            <div className="pt-4 mt-4 border-t">
              <h4 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">System Status</h4>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm">Video Processing</span>
                <span className="text-sm font-medium text-green-600 flex items-center">
                  <span className="h-2 w-2 rounded-full bg-green-500 mr-2 animate-pulse"></span>
                  Operational
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm">AI Face Verification</span>
                <span className="text-sm font-medium text-green-600 flex items-center">
                  <span className="h-2 w-2 rounded-full bg-green-500 mr-2 animate-pulse"></span>
                  Operational
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
