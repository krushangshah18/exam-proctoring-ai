'use client';

import { useEffect, useState, useRef, useCallback } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Loader2, ArrowRight, Sun, Volume2, CheckCircle2, XCircle, ScanFace, RefreshCw, ScanSearch } from 'lucide-react';
import { toast } from 'sonner';
import api from '@/lib/axios';

type CheckStatus = 'pending' | 'checking' | 'pass' | 'fail';

function CheckRow({
  icon, title, subtitle, status, onRetry, accent, errorHint,
}: {
  icon: React.ReactNode; title: string; subtitle: string; status: CheckStatus;
  onRetry: () => void; accent: string; errorHint?: string;
}) {
  return (
    <div style={{
      background: '#fff',
      border: `1.5px solid ${status === 'fail' ? 'rgba(239,68,68,0.25)' : status === 'pass' ? 'rgba(34,197,94,0.2)' : '#E2E8F0'}`,
      borderRadius: '10px', overflow: 'hidden',
      transition: 'border-color 200ms',
    }}>
      <div style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '36px', height: '36px', borderRadius: '9px', background: accent, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            {icon}
          </div>
          <div>
            <h3 style={{ fontSize: '13.5px', fontWeight: 700, color: '#0F172A' }}>{title}</h3>
            <p style={{ fontSize: '12px', color: '#64748B', marginTop: '1px' }}>{subtitle}</p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
          {status === 'checking' && <Loader2 style={{ width: '18px', height: '18px', color: '#22577A', animation: 'spin 1s linear infinite' }} />}
          {status === 'pass' && <CheckCircle2 style={{ width: '18px', height: '18px', color: '#22C55E' }} />}
          {status === 'fail' && (
            <>
              <XCircle style={{ width: '18px', height: '18px', color: '#EF4444' }} />
              <button
                onClick={onRetry}
                style={{
                  display: 'flex', alignItems: 'center', gap: '5px',
                  padding: '5px 10px', borderRadius: '6px', cursor: 'pointer',
                  background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
                  color: '#DC2626', fontSize: '12px', fontWeight: 600,
                  fontFamily: "'Plus Jakarta Sans', sans-serif",
                }}
              >
                <RefreshCw style={{ width: '11px', height: '11px' }} /> Retry
              </button>
            </>
          )}
          {status === 'pending' && (
            <div style={{ width: '18px', height: '18px', borderRadius: '50%', border: '2px solid #E2E8F0' }} />
          )}
        </div>
      </div>

      {/* Error hints for object detection failures */}
      {status === 'fail' && errorHint && (
        <div style={{
          margin: '0 14px 12px',
          padding: '9px 12px',
          borderRadius: '7px',
          background: 'rgba(239,68,68,0.05)',
          border: '1px solid rgba(239,68,68,0.15)',
          fontSize: '12px',
          color: '#DC2626',
          fontWeight: 500,
          lineHeight: 1.5,
        }}>
          {errorHint}
        </div>
      )}
    </div>
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
  const [faceStatus, setFaceStatus]   = useState<CheckStatus>('pending');
  const [objStatus, setObjStatus]     = useState<CheckStatus>('pending');
  const [noiseErrorHint, setNoiseErrorHint] = useState<string>('');
  const [objErrorHint, setObjErrorHint] = useState<string>('');

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

  const captureFrame = useCallback((): Promise<Blob> => {
    return new Promise((resolve, reject) => {
      if (!videoRef.current || !canvasRef.current) return reject(new Error('Video not ready'));
      const ctx = canvasRef.current.getContext('2d');
      if (!ctx) return reject(new Error('Canvas context unavailable'));
      ctx.drawImage(videoRef.current, 0, 0, 320, 240);
      canvasRef.current.toBlob(blob => {
        if (blob) resolve(blob);
        else reject(new Error('Failed to capture frame'));
      }, 'image/jpeg', 0.9);
    });
  }, []);

  const checkLighting = useCallback(async () => {
    setLightStatus('checking');
    await new Promise(r => setTimeout(r, 1500));
    if (!videoRef.current || !canvasRef.current) { setLightStatus('fail'); return; }
    const ctx = canvasRef.current.getContext('2d');
    if (!ctx) { setLightStatus('fail'); return; }
    ctx.drawImage(videoRef.current, 0, 0, 320, 240);
    const data = ctx.getImageData(0, 0, 320, 240).data;
    let sum = 0;
    for (let i = 0; i < data.length; i += 4) sum += (data[i] + data[i + 1] + data[i + 2]) / 3;
    const brightness = sum / (320 * 240);
    setLightStatus(brightness >= 40 ? 'pass' : 'fail');
    if (brightness < 40) toast.error('Room is too dark. Improve lighting and retry.');
  }, []);

  const checkNoise = useCallback(async (mediaStream: MediaStream) => {
    setNoiseStatus('checking');
    setNoiseErrorHint('');
    const ctx = new window.AudioContext();
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 2048;
    analyser.smoothingTimeConstant = 0.85;
    ctx.createMediaStreamSource(mediaStream).connect(analyser);
    const arr = new Float32Array(analyser.fftSize);

    await new Promise<void>(resolve => {
      const samples: number[] = [];
      const durationMs = 2500;
      const startedAt = performance.now();

      const tick = () => {
        analyser.getFloatTimeDomainData(arr);

        let sumSquares = 0;
        for (let i = 0; i < arr.length; i += 1) {
          sumSquares += arr[i] * arr[i];
        }
        const rms = Math.sqrt(sumSquares / arr.length);
        samples.push(rms);

        if (performance.now() - startedAt < durationMs) {
          requestAnimationFrame(tick);
          return;
        }

        const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
        const peak = Math.max(...samples);
        const loudFrames = samples.filter(level => level > 0.05).length;
        const loudRatio = loudFrames / samples.length;

        ctx.close();

        const failed = peak > 0.12 || avg > 0.035 || loudRatio > 0.3;

        if (failed) {
          setNoiseStatus('fail');
          setNoiseErrorHint('Too much continuous background sound was detected. Reduce fan noise, nearby voices, or other ambient audio and retry.');
          toast.error('Background noise is too high. Keep the room quieter and retry.');
        } else {
          setNoiseStatus('pass');
        }

        resolve();
      };

      tick();
    });
  }, []);

  const checkFace = useCallback(async () => {
    setFaceStatus('checking');
    try {
      const blob = await captureFrame();
      const form = new FormData();
      form.append('image', blob, 'capture.jpg');
      const res = await api.post(`/exam/${examId}/verify-face`, form, { headers: { 'Content-Type': 'multipart/form-data' } });
      setFaceStatus(res.data.verified ? 'pass' : 'fail');
      if (!res.data.verified) toast.error(res.data.message || 'Identity check failed. Reposition and retry.');
    } catch (err: any) {
      setFaceStatus('fail');
      toast.error(err.response?.data?.detail || err.message || 'Identity check failed.');
    }
  }, [examId, captureFrame]);

  const checkObjects = useCallback(async () => {
    setObjStatus('checking');
    setObjErrorHint('');
    try {
      // Small delay so the student is settled after face check
      await new Promise(r => setTimeout(r, 800));
      const blob = await captureFrame();
      const form = new FormData();
      form.append('image', blob, 'capture.jpg');
      const res = await api.post(`/exam/${examId}/check-objects`, form, { headers: { 'Content-Type': 'multipart/form-data' } });
      if (res.data.passed) {
        setObjStatus('pass');
      } else {
        setObjStatus('fail');
        const hint = res.data.issues.join(' ');
        setObjErrorHint(hint);
        toast.error(res.data.issues[0] || 'Object check failed.');
      }
    } catch (err: any) {
      setObjStatus('fail');
      const msg = err.response?.data?.detail || 'Object detection failed. Please retry.';
      setObjErrorHint(msg);
      toast.error(msg);
    }
  }, [examId, captureFrame]);

  useEffect(() => {
    const init = async () => {
      try {
        const s = await startStream();
        setLoading(false);
        await checkLighting();
        await checkNoise(s);
        await checkFace();
        await checkObjects();
      } catch {
        toast.error('Failed to access camera/microphone.');
        router.replace(`/student/exam/${examId}/device`);
      }
    };
    init();
    return () => { streamRef.current?.getTracks().forEach(t => t.stop()); };
  }, []);

  useEffect(() => {
    if (!loading && stream && videoRef.current) videoRef.current.srcObject = stream;
  }, [loading, stream]);

  const handleNext = () => router.push(`/student/exam/${examId}/system`);
  const allPassed   = lightStatus === 'pass' && noiseStatus === 'pass' && faceStatus === 'pass' && objStatus === 'pass';
  const anyChecking = [lightStatus, noiseStatus, faceStatus, objStatus].includes('checking');

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 style={{ width: '28px', height: '28px', color: '#22577A', animation: 'spin 1s linear infinite' }} />
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  return (
    <>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}} @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.6}}`}</style>
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px', background: '#F8FAFC' }}>
        <div style={{ maxWidth: '860px', margin: '0 auto' }} className="st-fadein">

          <div style={{ marginBottom: '24px' }}>
            <h1 style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.02em', marginBottom: '5px' }}>Environment Checklist</h1>
            <p style={{ fontSize: '14px', color: '#64748B' }}>Verifying your surroundings for exam integrity.</p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            {/* Camera preview */}
            <div style={{ aspectRatio: '4/3', position: 'relative', borderRadius: '12px', overflow: 'hidden', border: '1.5px solid #CBD5E1', boxShadow: '0 1px 4px rgba(15,23,42,0.08)', background: '#0F172A', lineHeight: 0 }}>
                <video
                  ref={videoRef}
                  autoPlay playsInline muted
                  style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', display: 'block', transform: 'scaleX(-1)' }}
                />
                <canvas ref={canvasRef} width={320} height={240} style={{ display: 'none' }} />

                {faceStatus === 'checking' && (
                  <div style={{ position: 'absolute', inset: '20px', border: '3px dashed rgba(87,204,153,0.6)', borderRadius: '12px', animation: 'pulse 1.5s ease-in-out infinite', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div style={{ background: 'rgba(0,0,0,0.7)', padding: '8px 16px', borderRadius: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ScanFace style={{ width: '16px', height: '16px', color: '#57CC99' }} />
                      <span style={{ fontSize: '12px', fontWeight: 700, color: '#fff' }}>Matching Identity</span>
                    </div>
                  </div>
                )}

                {objStatus === 'checking' && (
                  <div style={{ position: 'absolute', inset: '20px', border: '3px dashed rgba(147,51,234,0.6)', borderRadius: '12px', animation: 'pulse 1.5s ease-in-out infinite', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <div style={{ background: 'rgba(0,0,0,0.7)', padding: '8px 16px', borderRadius: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ScanSearch style={{ width: '16px', height: '16px', color: '#C084FC' }} />
                      <span style={{ fontSize: '12px', fontWeight: 700, color: '#fff' }}>Scanning Environment</span>
                    </div>
                  </div>
                )}
            </div>

            {/* Checks + proceed */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <CheckRow
                icon={<Sun style={{ width: '17px', height: '17px', color: '#D97706' }} />}
                accent="rgba(245,158,11,0.12)"
                title="Room Lighting"
                subtitle="Checking for clear visibility"
                status={lightStatus}
                onRetry={checkLighting}
              />
              <CheckRow
                icon={<Volume2 style={{ width: '17px', height: '17px', color: '#0284C7' }} />}
                accent="rgba(2,132,199,0.1)"
                title="Background Noise"
                subtitle="Monitoring for quiet environment"
                status={noiseStatus}
                onRetry={() => streamRef.current && checkNoise(streamRef.current)}
                errorHint={noiseErrorHint}
              />
              <CheckRow
                icon={<ScanFace style={{ width: '17px', height: '17px', color: '#22C55E' }} />}
                accent="rgba(34,197,94,0.1)"
                title="Identity Verification"
                subtitle="Matching face with account profile"
                status={faceStatus}
                onRetry={checkFace}
              />
              <CheckRow
                icon={<ScanSearch style={{ width: '17px', height: '17px', color: '#9333EA' }} />}
                accent="rgba(147,51,234,0.08)"
                title="Object Detection"
                subtitle="Scanning for prohibited items in frame"
                status={objStatus}
                onRetry={checkObjects}
                errorHint={objErrorHint}
              />

              <button
                onClick={handleNext}
                disabled={!allPassed || anyChecking}
                className="st-btn st-btn-lg"
                style={{ width: '100%', marginTop: 'auto' }}
              >
                {anyChecking
                  ? <><Loader2 style={{ width: '16px', height: '16px', animation: 'spin 1s linear infinite' }} /> Analyzing Environment…</>
                  : allPassed
                  ? <>Proceed to System Checks <ArrowRight style={{ width: '16px', height: '16px' }} /></>
                  : 'Fix Failed Checks Above'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
