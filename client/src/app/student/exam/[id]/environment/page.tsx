'use client';

import { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Loader2, ArrowRight, Sun, Volume2, CheckCircle2, XCircle, ScanFace, RefreshCw, Box } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import api from '@/lib/axios';

type CheckStatus = 'pending' | 'checking' | 'pass' | 'fail';

function CheckRow({
  icon,
  title,
  subtitle,
  iconBg,
  iconColor,
  status,
  onRetry,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  iconBg: string;
  iconColor: string;
  status: CheckStatus;
  onRetry: () => void;
}) {
  return (
    <Card className="p-4 flex items-center justify-between border-slate-200">
      <div className="flex items-center gap-4">
        <div className={`${iconBg} p-2 rounded-lg`}>
          <div className={iconColor}>{icon}</div>
        </div>
        <div>
          <h3 className="font-semibold text-slate-900">{title}</h3>
          <p className="text-sm text-slate-500">{subtitle}</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {status === 'checking' && <Loader2 className="h-5 w-5 animate-spin text-indigo-500" />}
        {status === 'pass' && <CheckCircle2 className="h-5 w-5 text-emerald-500" />}
        {status === 'fail' && (
          <>
            <XCircle className="h-5 w-5 text-rose-500" />
            <Button
              size="sm"
              variant="outline"
              onClick={onRetry}
              className="h-7 gap-1 text-xs border-rose-200 text-rose-700 hover:bg-rose-50"
            >
              <RefreshCw className="h-3 w-3" /> Retry
            </Button>
          </>
        )}
        {status === 'pending' && (
          <div className="h-5 w-5 rounded-full border-2 border-slate-200" />
        )}
      </div>
    </Card>
  );
}

export default function EnvironmentCheckPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);

  const [stream, setStream] = useState<MediaStream | null>(null);
  const [loading, setLoading] = useState(true);

  const [lightStatus, setLightStatus] = useState<CheckStatus>('pending');
  const [noiseStatus, setNoiseStatus] = useState<CheckStatus>('pending');
  const [faceStatus, setFaceStatus] = useState<CheckStatus>('pending');

  const startStream = useCallback(async () => {
    const camId = localStorage.getItem(`exam_cam_${examId}`);
    const micId = localStorage.getItem(`exam_mic_${examId}`);
    const s = await navigator.mediaDevices.getUserMedia({
      video: { deviceId: camId ? { exact: camId } : undefined },
      audio: { deviceId: micId ? { exact: micId } : undefined },
    });
    streamRef.current = s;
    setStream(s);
    return s;
  }, [examId]);

  // --- Individual check functions ---

  const checkLighting = useCallback(async () => {
    setLightStatus('checking');
    await new Promise((r) => setTimeout(r, 1500));
    if (!videoRef.current || !canvasRef.current) {
      setLightStatus('fail');
      return;
    }
    const ctx = canvasRef.current.getContext('2d');
    if (!ctx) { setLightStatus('fail'); return; }
    ctx.drawImage(videoRef.current, 0, 0, 320, 240);
    const data = ctx.getImageData(0, 0, 320, 240).data;
    let sum = 0;
    for (let i = 0; i < data.length; i += 4) {
      sum += (data[i] + data[i + 1] + data[i + 2]) / 3;
    }
    const brightness = sum / (320 * 240);
    setLightStatus(brightness >= 40 ? 'pass' : 'fail');
    if (brightness < 40) toast.error('Room is too dark. Improve lighting and retry.');
  }, []);

  const checkNoise = useCallback(async (mediaStream: MediaStream) => {
    setNoiseStatus('checking');
    const ctx = new window.AudioContext();
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 256;
    ctx.createMediaStreamSource(mediaStream).connect(analyser);
    const arr = new Uint8Array(analyser.frequencyBinCount);

    await new Promise<void>((resolve) => {
      let cycles = 0;
      let peak = 0;
      const tick = () => {
        analyser.getByteFrequencyData(arr);
        const vol = arr.reduce((a, b) => a + b, 0) / arr.length;
        if (vol > peak) peak = vol;
        if (++cycles < 60) requestAnimationFrame(tick);
        else {
          ctx.close();
          setNoiseStatus(peak > 70 ? 'fail' : 'pass');
          if (peak > 70) toast.error('Background noise too high. Find a quieter spot.');
          resolve();
        }
      };
      tick();
    });
  }, []);

  const checkFace = useCallback(async () => {
    setFaceStatus('checking');
    try {
      if (!videoRef.current || !canvasRef.current) throw new Error('Video not ready');
      const ctx = canvasRef.current.getContext('2d');
      if (!ctx) throw new Error('Canvas context unavailable');
      ctx.drawImage(videoRef.current, 0, 0, 320, 240);
      const blob = await new Promise<Blob | null>((resolve) =>
        canvasRef.current!.toBlob(resolve, 'image/jpeg', 0.9)
      );
      if (!blob) throw new Error('Failed to capture image');
      const form = new FormData();
      form.append('image', blob, 'capture.jpg');
      const res = await api.post(`/exam/${examId}/verify-face`, form, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setFaceStatus(res.data.verified ? 'pass' : 'fail');
      if (!res.data.verified) toast.error(res.data.message || 'Identity check failed. Reposition and retry.');
    } catch (err: any) {
      setFaceStatus('fail');
      toast.error(err.response?.data?.detail || err.message || 'Identity check failed.');
    }
  }, [examId]);

  // Initial load: open stream then run all checks in sequence
  useEffect(() => {
    const init = async () => {
      try {
        const s = await startStream();
        setLoading(false);
        await checkLighting();
        await checkNoise(s);
        await checkFace();
      } catch {
        toast.error('Failed to access camera/microphone.');
        router.replace(`/student/exam/${examId}/device`);
      }
    };
    init();
    return () => {
      streamRef.current?.getTracks().forEach((t) => t.stop());
    };
  }, []);

  useEffect(() => {
    if (!loading && stream && videoRef.current) {
      videoRef.current.srcObject = stream;
    }
  }, [loading, stream]);

  const handleNext = () => router.push(`/student/exam/${examId}/system`);

  const allPassed = lightStatus === 'pass' && noiseStatus === 'pass' && faceStatus === 'pass';
  const anyChecking = [lightStatus, noiseStatus, faceStatus].includes('checking');

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  return (
    <div className="flex-1 flex overflow-hidden">
      <div className="flex-1 overflow-y-auto p-6 md:p-12">
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Environment Checklist</h1>
            <p className="text-lg text-slate-600">Verifying your surroundings for exam integrity.</p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {/* Camera preview */}
            <Card className="p-4 bg-slate-900 border-slate-800 overflow-hidden">
              <div className="aspect-video bg-black rounded-lg overflow-hidden flex items-center justify-center relative">
                <video
                  ref={videoRef}
                  autoPlay
                  playsInline
                  muted
                  className="w-full h-full object-cover"
                  style={{ transform: 'scaleX(-1)' }}
                />
                <canvas ref={canvasRef} width={320} height={240} className="hidden" />
                {faceStatus === 'checking' && (
                  <div className="absolute inset-0 border-4 border-indigo-500/50 border-dashed rounded-xl m-8 animate-pulse shadow-[0_0_20px_rgba(99,102,241,0.5)]">
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-white font-bold bg-black/60 px-4 py-2 rounded-full flex gap-2 items-center">
                      <ScanFace className="h-5 w-5 animate-bounce" /> Matching Identity
                    </div>
                  </div>
                )}
              </div>
            </Card>

            {/* Check list */}
            <div className="space-y-4">
              <CheckRow
                icon={<Sun className="h-5 w-5" />}
                iconBg="bg-amber-100"
                iconColor="text-amber-600"
                title="Room Lighting"
                subtitle="Checking for clear visibility"
                status={lightStatus}
                onRetry={checkLighting}
              />

              <CheckRow
                icon={<Volume2 className="h-5 w-5" />}
                iconBg="bg-sky-100"
                iconColor="text-sky-600"
                title="Background Noise"
                subtitle="Monitoring for quiet environment"
                status={noiseStatus}
                onRetry={() => streamRef.current && checkNoise(streamRef.current)}
              />

              <CheckRow
                icon={<ScanFace className="h-5 w-5" />}
                iconBg="bg-emerald-100"
                iconColor="text-emerald-600"
                title="Identity Verification"
                subtitle="Matching face with account profile"
                status={faceStatus}
                onRetry={checkFace}
              />

              {/* Object Detection stub */}
              <Card className="p-4 flex items-center justify-between border-slate-200 opacity-60">
                <div className="flex items-center gap-4">
                  <div className="bg-purple-100 p-2 rounded-lg">
                    <Box className="h-5 w-5 text-purple-600" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-slate-900">Object Detection</h3>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0 bg-purple-50 text-purple-700 border-purple-200">
                        Coming Soon
                      </Badge>
                    </div>
                    <p className="text-sm text-slate-500">Scanning for prohibited items — model integration pending</p>
                  </div>
                </div>
                <div className="h-5 w-5 rounded-full border-2 border-dashed border-slate-300" />
              </Card>

              <div className="pt-4">
                <Button
                  onClick={handleNext}
                  disabled={!allPassed || anyChecking}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 transition-all"
                  size="lg"
                >
                  {anyChecking
                    ? 'Analyzing Environment…'
                    : allPassed
                    ? 'Proceed to System Checks'
                    : 'Fix Failed Checks Above'}
                  {allPassed && !anyChecking && <ArrowRight className="h-4 w-4 ml-2" />}
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
