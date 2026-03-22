'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Camera, Mic, Loader2, ArrowRight, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';

export default function DeviceSelectionPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const videoRef = useRef<HTMLVideoElement>(null);
  const animFrameRef = useRef<number>(0);

  const [devices, setDevices] = useState<{ cameras: MediaDeviceInfo[]; mics: MediaDeviceInfo[] }>({
    cameras: [],
    mics: [],
  });
  const [selectedCam, setSelectedCam] = useState<string>('');
  const [selectedMic, setSelectedMic] = useState<string>('');
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(true);

  // Audio level meter (0–100)
  const [audioLevel, setAudioLevel] = useState(0);
  const audioCtxRef = useRef<AudioContext | null>(null);

  // Initial permission request + device enumeration
  useEffect(() => {
    let baseStream: MediaStream | null = null;

    const initDevices = async () => {
      try {
        baseStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        const allDevices = await navigator.mediaDevices.enumerateDevices();
        const cameras = allDevices.filter((d) => d.kind === 'videoinput');
        const mics = allDevices.filter((d) => d.kind === 'audioinput');

        setDevices({ cameras, mics });
        if (cameras.length > 0) setSelectedCam(cameras[0].deviceId);
        if (mics.length > 0) setSelectedMic(mics[0].deviceId);
        setLoading(false);
      } catch {
        setError(
          'Camera and Microphone permissions are required. Please allow access in your browser settings and refresh.'
        );
        setLoading(false);
      } finally {
        // Stop the base permission stream — we'll open a proper one via selectedCam/Mic effect
        if (baseStream) baseStream.getTracks().forEach((t) => t.stop());
      }
    };

    initDevices();

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      if (audioCtxRef.current && audioCtxRef.current.state !== 'closed') {
        audioCtxRef.current.close();
      }
    };
  }, []);

  // Update live preview + audio meter when device selection changes
  useEffect(() => {
    if (!selectedCam || !selectedMic) return;

    let activeStream: MediaStream | null = null;
    let localCtx: AudioContext | null = null;

    const updateStream = async () => {
      // Tear down previous audio context
      cancelAnimationFrame(animFrameRef.current);
      audioCtxRef.current?.close();

      try {
        activeStream = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: { exact: selectedCam } },
          audio: { deviceId: { exact: selectedMic } },
        });

        setStream(activeStream);
        if (videoRef.current) videoRef.current.srcObject = activeStream;

        // Build audio analyser
        localCtx = new window.AudioContext();
        audioCtxRef.current = localCtx;
        const analyser = localCtx.createAnalyser();
        analyser.fftSize = 256;
        const source = localCtx.createMediaStreamSource(activeStream);
        source.connect(analyser);

        const data = new Uint8Array(analyser.frequencyBinCount);
        const tick = () => {
          analyser.getByteFrequencyData(data);
          const avg = data.reduce((a, b) => a + b, 0) / data.length;
          setAudioLevel(Math.min(100, Math.round((avg / 128) * 100)));
          animFrameRef.current = requestAnimationFrame(tick);
        };
        tick();
      } catch (err) {
        console.error('Stream update error:', err);
      }
    };

    updateStream();

    return () => {
      cancelAnimationFrame(animFrameRef.current);
      if (localCtx && localCtx.state !== 'closed') localCtx.close();
      if (activeStream) activeStream.getTracks().forEach((t) => t.stop());
    };
  }, [selectedCam, selectedMic]);

  const handleNext = () => {
    localStorage.setItem(`exam_cam_${examId}`, selectedCam);
    localStorage.setItem(`exam_mic_${examId}`, selectedMic);
    if (stream) stream.getTracks().forEach((t) => t.stop());
    cancelAnimationFrame(animFrameRef.current);
    if (audioCtxRef.current && audioCtxRef.current.state !== 'closed') audioCtxRef.current.close();
    router.push(`/student/exam/${examId}/environment`);
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center p-24">
        <Loader2 className="h-8 w-8 animate-spin text-slate-400" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="text-center max-w-md">
          <AlertTriangle className="h-12 w-12 text-rose-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-slate-900 mb-2">Hardware Access Denied</h2>
          <p className="text-slate-500 mb-6">{error}</p>
          <Button onClick={() => window.location.reload()} variant="outline">
            Try Again
          </Button>
        </div>
      </div>
    );
  }

  // Determine mic bar color
  const micBarColor =
    audioLevel > 75 ? 'bg-rose-500' : audioLevel > 40 ? 'bg-amber-400' : 'bg-emerald-500';

  return (
    <div className="flex-1 flex overflow-hidden">
      <div className="flex-1 overflow-y-auto p-6 md:p-12">
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Hardware Setup</h1>
            <p className="text-lg text-slate-600">Select and test your camera and microphone</p>
          </div>

          <div className="grid md:grid-cols-2 gap-8">
            {/* Camera preview */}
            <Card className="p-4 bg-slate-900 overflow-hidden">
              <div className="aspect-video bg-black rounded-lg overflow-hidden flex items-center justify-center relative">
                <video
                  ref={videoRef}
                  autoPlay
                  playsInline
                  muted
                  className="w-full h-full object-cover"
                  style={{ transform: 'scaleX(-1)' }}
                />
                {!stream && <Loader2 className="absolute h-8 w-8 animate-spin text-slate-400" />}
              </div>
            </Card>

            {/* Controls */}
            <div className="space-y-6">
              {/* Camera selector */}
              <div className="space-y-2">
                <label className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                  <Camera className="h-4 w-4" /> Select Camera
                </label>
                <Select value={selectedCam} onValueChange={setSelectedCam}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select Camera" />
                  </SelectTrigger>
                  <SelectContent>
                    {devices.cameras.map((cam) => (
                      <SelectItem key={cam.deviceId} value={cam.deviceId}>
                        {cam.label || `Camera ${cam.deviceId.slice(0, 5)}…`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Microphone selector + live audio meter */}
              <div className="space-y-3">
                <label className="text-sm font-semibold text-slate-700 flex items-center gap-2">
                  <Mic className="h-4 w-4" /> Select Microphone
                </label>
                <Select value={selectedMic} onValueChange={setSelectedMic}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select Microphone" />
                  </SelectTrigger>
                  <SelectContent>
                    {devices.mics.map((mic) => (
                      <SelectItem key={mic.deviceId} value={mic.deviceId}>
                        {mic.label || `Microphone ${mic.deviceId.slice(0, 5)}…`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>

                {/* Audio level bar */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-xs text-slate-500">
                    <span>Microphone Input Level</span>
                    <span>{audioLevel}%</span>
                  </div>
                  <div className="h-3 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200">
                    <div
                      className={`h-full rounded-full transition-all duration-75 ${micBarColor}`}
                      style={{ width: `${audioLevel}%` }}
                    />
                  </div>
                  <p className="text-xs text-slate-400">
                    {audioLevel === 0
                      ? 'No input detected — speak to test'
                      : audioLevel > 75
                      ? 'Volume too high — move away or lower mic gain'
                      : 'Microphone working correctly'}
                  </p>
                </div>
              </div>

              <div className="pt-4">
                <Button
                  onClick={handleNext}
                  disabled={!selectedCam || !selectedMic}
                  className="w-full bg-indigo-600 hover:bg-indigo-700"
                  size="lg"
                >
                  Confirm & Proceed <ArrowRight className="h-4 w-4 ml-2" />
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
