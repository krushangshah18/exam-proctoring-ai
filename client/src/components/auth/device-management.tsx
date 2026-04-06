'use client';

import { useEffect, useState } from 'react';
import { Laptop, Smartphone, Trash2, ShieldCheck } from 'lucide-react';
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
import { fmtDateTimeIST } from '@/lib/fmt-date';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';

import { jwtDecode } from 'jwt-decode';

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

interface JWTPayload {
  device: string;
}

export default function DeviceManagement() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentFingerprint, setCurrentFingerprint] = useState<string | null>(null);
  const [deviceToRevoke, setDeviceToRevoke] = useState<Device | null>(null);

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
    // Get current device fingerprint from token
    const token = localStorage.getItem('access_token');
    if (token) {
      try {
        const decoded = jwtDecode<JWTPayload>(token);
        setCurrentFingerprint(decoded.device);
      } catch (e) {
        console.error("Failed to decode token", e);
      }
    }
    fetchDevices();
  }, []);

  const handleRevoke = async (deviceId: string) => {
    try {
      await api.post(`/auth/devices/${deviceId}/revoke`);
      toast.success("Device revoked successfully");
      setDeviceToRevoke(null);
      fetchDevices(); // Refresh list
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
    <>
      <Card className="w-full max-w-4xl mx-auto mt-8">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Laptop className="h-6 w-6" />
            Active Sessions & Devices
          </CardTitle>
          <CardDescription className="text-slate-600">
            Manage the devices that have accessed your account.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {devices.map((device) => {
              const isCurrent = device.fingerprint === currentFingerprint;
              return (
                <div
                  key={device.id}
                  className={`flex items-center justify-between p-4 border rounded-lg transition-colors ${
                    isCurrent
                      ? 'bg-primary/5 border-primary/20'
                      : 'bg-card hover:bg-accent/10'
                  }`}
                >
                  <div className="flex items-start gap-4">
                    <div className={`p-2 rounded-full ${isCurrent ? 'bg-primary/10 text-primary' : 'bg-secondary'}`}>
                      {device.user_agent.toLowerCase().includes('mobile') ? <Smartphone className="h-5 w-5" /> : <Laptop className="h-5 w-5" />}
                    </div>
                    <div>
                      <div className="font-medium flex items-center gap-2">
                        {device.ip_address}
                        {isCurrent && (
                          <Badge className="bg-primary hover:bg-primary/90">Current Device</Badge>
                        )}
                        {device.trusted ? (
                          <Badge variant="secondary" className="text-green-600 bg-green-100 dark:bg-green-900/30">
                            <ShieldCheck className="w-3 h-3 mr-1" /> Trusted
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-yellow-600">Pending</Badge>
                        )}
                        {device.revoked && <Badge variant="destructive">Revoked</Badge>}
                      </div>
                      <p className="max-w-md truncate text-sm text-slate-500" title={device.user_agent}>
                        {device.user_agent}
                      </p>
                      <p className="mt-1 text-xs text-slate-600">
                        Last active: {fmtDateTimeIST(device.last_seen)}
                      </p>
                    </div>
                  </div>

                  {!device.revoked && !isCurrent && (
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => setDeviceToRevoke(device)}
                    >
                      <Trash2 className="h-4 w-4 mr-1" />
                      Revoke
                    </Button>
                  )}
                </div>
              );
            })}
            {devices.length === 0 && (
              <p className="text-center text-slate-600">No device history found.</p>
            )}
          </div>
        </CardContent>
      </Card>

      <ConfirmDialog
        isOpen={!!deviceToRevoke}
        onOpenChange={(open) => {
          if (!open) setDeviceToRevoke(null);
        }}
        title="Revoke device access?"
        description={
          deviceToRevoke
            ? `This will immediately sign out the device at ${deviceToRevoke.ip_address}.`
            : 'This will immediately sign out the selected device.'
        }
        confirmLabel="Revoke Device"
        cancelLabel="Cancel"
        variant="destructive"
        onConfirm={() => { if (deviceToRevoke) handleRevoke(deviceToRevoke.id); }}
      />
    </>
  );
}
