'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import RoleGuard from '@/components/auth/role-guard';
import Webcam from 'react-webcam';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Avatar } from '@/components/ui/avatar';
import { Camera, User, Lock, ArrowLeft, Loader2, RefreshCw, CheckCircle2 } from 'lucide-react';
import { useRouter } from 'next/navigation';
import api from '@/lib/axios';
import { toast } from 'sonner';
import { Separator } from '@/components/ui/separator';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

export default function StudentProfile() {
  const router = useRouter();
  const webcamRef = useRef<Webcam>(null);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  
  // Webcam dialog state
  const [showWebcam, setShowWebcam] = useState(false);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  
  // Profile update state
  const [fullName, setFullName] = useState('');
  
  // Password change state
  const [passwordData, setPasswordData] = useState({
    old_password: '',
    new_password: '',
    confirm_password: ''
  });

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const res = await api.get('/auth/me');
      console.log('User profile data:', res.data);
      console.log('Profile image path:', res.data.profile_image_path);
      setUser(res.data);
      setFullName(res.data.full_name || '');
    } catch (error) {
      console.error('Failed to fetch user profile', error);
      toast.error('Failed to load profile');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateProfile = async () => {
    if (!fullName.trim()) {
      toast.error('Full name cannot be empty');
      return;
    }

    setUpdating(true);
    try {
      await api.put('/auth/me/profile', { full_name: fullName });
      toast.success('Profile updated successfully');
      fetchUserProfile();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to update profile');
    } finally {
      setUpdating(false);
    }
  };

  const handleChangePassword = async () => {
    if (!passwordData.old_password || !passwordData.new_password) {
      toast.error('Please fill in all password fields');
      return;
    }

    if (passwordData.new_password !== passwordData.confirm_password) {
      toast.error('New passwords do not match');
      return;
    }

    if (passwordData.new_password.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }

    setUpdating(true);
    try {
      await api.post('/auth/change-password', {
        old_password: passwordData.old_password,
        new_password: passwordData.new_password
      });
      toast.success('Password changed successfully');
      setPasswordData({ old_password: '', new_password: '', confirm_password: '' });
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to change password');
    } finally {
      setUpdating(false);
    }
  };

  const capture = useCallback(() => {
    const imageSrc = webcamRef.current?.getScreenshot();
    if (imageSrc) {
      setImgSrc(imageSrc);
    }
  }, [webcamRef]);

  const retake = () => {
    setImgSrc(null);
  };

  const handleProfileImageUpload = async () => {
    if (!imgSrc) {
      toast.error('Please capture a selfie first');
      return;
    }

    setUpdating(true);
    try {
      // Convert base64 to blob
      const res = await fetch(imgSrc);
      const blob = await res.blob();
      const file = new File([blob], "selfie.jpg", { type: "image/jpeg" });

      const formData = new FormData();
      formData.append('selfie', file);

      await api.put('/auth/me/profile-image', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      
      toast.success('Profile image updated successfully');
      setShowWebcam(false);
      setImgSrc(null);
      fetchUserProfile();
    } catch (error: any) {
      const msg = error.response?.data?.detail || 'Failed to update profile image';
      toast.error(msg);
    } finally {
      setUpdating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <RoleGuard allowedRoles={['STUDENT']}>
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        {/* Header */}
        <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
          <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center h-16">
              <Button variant="ghost" size="sm" onClick={() => router.push('/student/dashboard')}>
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Dashboard
              </Button>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="mb-8">
            <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">
              Profile Settings
            </h2>
            <p className="text-gray-600 dark:text-gray-400">
              Manage your account settings and preferences
            </p>
          </div>

          {/* Profile Image */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Camera className="h-5 w-5" />
                Profile Image
              </CardTitle>
              <CardDescription>
                Update your profile picture using webcam. Face verification is required. (Can be updated once every 30 days)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-6">
                <Avatar className="h-24 w-24">
                  {user?.profile_image_path ? (
                    <img 
                      src={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/${user.profile_image_path}`} 
                      alt="Profile" 
                      className="w-full h-full object-cover"
                      onError={(e) => {
                        // Fallback to avatar if image fails to load
                        e.currentTarget.style.display = 'none';
                      }}
                    />
                  ) : null}
                  {!user?.profile_image_path && (
                    <div className="w-full h-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white text-3xl font-bold">
                      {user?.full_name?.charAt(0) || 'S'}
                    </div>
                  )}
                </Avatar>
                <div>
                  <Button
                    onClick={() => setShowWebcam(true)}
                    disabled={updating}
                  >
                    <Camera className="mr-2 h-4 w-4" />
                    Take New Selfie
                  </Button>
                  <p className="text-sm text-gray-500 mt-2">
                    Capture a clear selfie for verification
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Basic Information */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                Basic Information
              </CardTitle>
              <CardDescription>
                Update your personal information
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  value={user?.email || ''}
                  disabled
                  className="bg-gray-100 dark:bg-gray-800"
                />
                <p className="text-xs text-gray-500 mt-1">Email cannot be changed</p>
              </div>
              <div>
                <Label htmlFor="fullName">Full Name</Label>
                <Input
                  id="fullName"
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Enter your full name"
                />
              </div>
              <Button onClick={handleUpdateProfile} disabled={updating}>
                {updating ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Updating...
                  </>
                ) : (
                  'Update Profile'
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Change Password */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Change Password
              </CardTitle>
              <CardDescription>
                Update your password to keep your account secure
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="oldPassword">Current Password</Label>
                <Input
                  id="oldPassword"
                  type="password"
                  value={passwordData.old_password}
                  onChange={(e) => setPasswordData({ ...passwordData, old_password: e.target.value })}
                  placeholder="Enter current password"
                />
              </div>
              <Separator />
              <div>
                <Label htmlFor="newPassword">New Password</Label>
                <Input
                  id="newPassword"
                  type="password"
                  value={passwordData.new_password}
                  onChange={(e) => setPasswordData({ ...passwordData, new_password: e.target.value })}
                  placeholder="Enter new password (min 8 characters)"
                />
              </div>
              <div>
                <Label htmlFor="confirmPassword">Confirm New Password</Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  value={passwordData.confirm_password}
                  onChange={(e) => setPasswordData({ ...passwordData, confirm_password: e.target.value })}
                  placeholder="Confirm new password"
                />
              </div>
              <Button onClick={handleChangePassword} disabled={updating}>
                {updating ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Changing...
                  </>
                ) : (
                  'Change Password'
                )}
              </Button>
            </CardContent>
          </Card>
        </main>

        {/* Webcam Dialog */}
        <Dialog open={showWebcam} onOpenChange={setShowWebcam}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle>Capture Selfie</DialogTitle>
              <DialogDescription>
                Take a clear selfie for face verification
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="relative aspect-video w-full overflow-hidden rounded-lg border bg-black">
                {!imgSrc ? (
                  <Webcam
                    audio={false}
                    ref={webcamRef}
                    screenshotFormat="image/jpeg"
                    videoConstraints={{ facingMode: "user" }}
                    className="h-full w-full object-cover"
                  />
                ) : (
                  <img 
                    src={imgSrc} 
                    alt="Selfie" 
                    className="h-full w-full object-cover" 
                  />
                )}
              </div>

              <div className="flex justify-center gap-4">
                {!imgSrc ? (
                  <Button type="button" onClick={capture} variant="secondary">
                    <Camera className="mr-2 h-4 w-4" />
                    Capture
                  </Button>
                ) : (
                  <Button type="button" onClick={retake} variant="outline">
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Retake
                  </Button>
                )}
              </div>

              <div className="flex gap-4">
                <Button 
                  type="button" 
                  variant="ghost" 
                  onClick={() => {
                    setShowWebcam(false);
                    setImgSrc(null);
                  }}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button 
                  onClick={handleProfileImageUpload} 
                  disabled={!imgSrc || updating}
                  className="flex-1"
                >
                  {updating ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Uploading...
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="mr-2 h-4 w-4" />
                      Upload
                    </>
                  )}
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </RoleGuard>
  );
}
