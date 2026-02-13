'use client';

import { useEffect, useState } from 'react';
import { Laptop, Smartphone, Trash2, ShieldCheck, ShieldAlert, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import api from '@/lib/axios';

interface Device {
  id: string;
  fingerprint: string;
  user_agent: string;
  ip_address: string;
  last_seen: string;
  trusted: boolean;
  revoked: boolean;
  created_at: string;
}

export default function DeviceManagement() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDevices = async () => {
    try {
      const res = await api.get('/auth/devices/me');
      setDevices(res.data);
    } catch (error) {
      console.error("Failed to fetch devices", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDevices();
  }, []);

  const handleRevoke = async (deviceId: string) => {
    if (!confirm("Are you sure you want to revoke this device? It will be logged out immediately.")) return;

    try {
      await api.post(`/auth/devices/${deviceId}/revoke`);
      toast.success("Device revoked successfully");
      // Refresh list
      fetchDevices();
    } catch (error: any) {
      console.error(error);
      toast.error(error.response?.data?.detail || "Failed to revoke device");
    }
  };

  if (loading) return (
    <div className="flex justify-center p-8">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900 dark:border-white"></div>
    </div>
  );

  return (
    <Card className="w-full max-w-4xl mx-auto mt-8">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Laptop className="h-6 w-6" />
          Active Sessions & Devices
        </CardTitle>
        <CardDescription>
          Manage the devices that have accessed your account.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {devices.map((device) => {
             const isCurrent = false; // We can't easily tell without comparing fingerprint from token, but backend prevents self-revoke
             return (
            <div
              key={device.id}
              className="flex items-center justify-between p-4 border rounded-lg bg-card hover:bg-accent/10 transition-colors"
            >
              <div className="flex items-start gap-4">
                <div className="p-2 bg-secondary rounded-full">
                   {device.user_agent.toLowerCase().includes('mobile') ? <Smartphone className="h-5 w-5" /> : <Laptop className="h-5 w-5" />}
                </div>
                <div>
                  <div className="font-medium flex items-center gap-2">
                    {device.ip_address}
                    {device.trusted ? (
                      <Badge variant="secondary" className="text-green-600 bg-green-100 dark:bg-green-900/30">
                        <ShieldCheck className="w-3 h-3 mr-1" /> Trusted
                      </Badge>
                    ) : (
                       <Badge variant="outline" className="text-yellow-600">Pending</Badge>
                    )}
                    {device.revoked && <Badge variant="destructive">Revoked</Badge>}
                  </div>
                  <p className="text-sm text-muted-foreground truncate max-w-md" title={device.user_agent}>
                    {device.user_agent}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Last active: {new Date(device.last_seen).toLocaleString()}
                  </p>
                </div>
              </div>
              
              {!device.revoked && (
                <Button 
                  variant="destructive" 
                  size="sm"
                  onClick={() => handleRevoke(device.id)}
                >
                  <Trash2 className="h-4 w-4 mr-1" />
                  Revoke
                </Button>
              )}
            </div>
          )})}
          {devices.length === 0 && (
             <p className="text-center text-muted-foreground">No device history found.</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
