'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { Camera, Mic, Loader2, ArrowRight, AlertTriangle } from 'lucide-react';

export default function DeviceSelectionPage() {
  const router = useRouter();
  const params = useParams();
  const examId = params.id as string;

  const videoRef = useRef<HTMLVideoElement>(null);
  const animFrameRef = useRef<number>(0);

  const [devices, setDevices] = useState<{ cameras: MediaDeviceInfo[]; mics: MediaDeviceInfo[] }>({ cameras: [], mics: [] });
  const [selectedCam, setSelectedCam] = useState<string>('');
  const [selectedMic, setSelectedMic] = useState<string>('');
  const [stream, setStream] = useState<MediaStream | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(true);
  const [audioLevel, setAudioLevel] = useState(0);
  const audioCtxRef = useRef<AudioContext | null>(null);

  useEffect(() => {
    let baseStream: MediaStream | null = null;
    const initDevices = async () => {
      try {
        baseStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        const allDevices = await navigator.mediaDevices.enumerateDevices();
        const cameras = allDevices.filter(d => d.kind === 'videoinput');
        const mics = allDevices.filter(d => d.kind === 'audioinput');
        setDevices({ cameras, mics });
        if (cameras.length > 0) setSelectedCam(cameras[0].deviceId);
        if (mics.length > 0) setSelectedMic(mics[0].deviceId);
        setLoading(false);
      } catch {
        setError('Camera and Microphone permissions are required. Please allow access in your browser settings and refresh.');
        setLoading(false);
      } finally {
        if (baseStream) baseStream.getTracks().forEach(t => t.stop());
      }
    };
    initDevices();
    return () => {
      cancelAnimationFrame(animFrameRef.current);
      if (audioCtxRef.current && audioCtxRef.current.state !== 'closed') audioCtxRef.current.close();
    };
  }, []);

  useEffect(() => {
    if (!selectedCam || !selectedMic) return;
    let activeStream: MediaStream | null = null;
    let localCtx: AudioContext | null = null;

    const updateStream = async () => {
      cancelAnimationFrame(animFrameRef.current);
      audioCtxRef.current?.close();
      try {
        activeStream = await navigator.mediaDevices.getUserMedia({
          video: { deviceId: { exact: selectedCam } },
          audio: { deviceId: { exact: selectedMic } },
        });
        setStream(activeStream);
        if (videoRef.current) videoRef.current.srcObject = activeStream;
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
      } catch (err) { console.error('Stream update error:', err); }
    };
    updateStream();
    return () => {
      cancelAnimationFrame(animFrameRef.current);
      if (localCtx && localCtx.state !== 'closed') localCtx.close();
      if (activeStream) activeStream.getTracks().forEach(t => t.stop());
    };
  }, [selectedCam, selectedMic]);

  const handleNext = () => {
    localStorage.setItem(`exam_cam_${examId}`, selectedCam);
    localStorage.setItem(`exam_mic_${examId}`, selectedMic);
    if (stream) stream.getTracks().forEach(t => t.stop());
    cancelAnimationFrame(animFrameRef.current);
    if (audioCtxRef.current && audioCtxRef.current.state !== 'closed') audioCtxRef.current.close();
    router.push(`/student/exam/${examId}/environment`);
  };

  const micBarColor = audioLevel > 75 ? '#EF4444' : audioLevel > 40 ? '#F59E0B' : '#22C55E';

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Loader2 style={{ width: '28px', height: '28px', color: '#22577A', animation: 'spin 1s linear infinite' }} />
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
        <div style={{ textAlign: 'center', maxWidth: '380px' }}>
          <AlertTriangle style={{ width: '48px', height: '48px', color: '#EF4444', margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: '20px', fontWeight: 800, color: '#0F172A', marginBottom: '8px' }}>Hardware Access Denied</h2>
          <p style={{ fontSize: '14px', color: '#64748B', marginBottom: '20px' }}>{error}</p>
          <button onClick={() => window.location.reload()} className="st-btn-ghost">Try Again</button>
        </div>
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  return (
    <>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px', background: '#F8FAFC' }}>
        <div style={{ maxWidth: '860px', margin: '0 auto' }} className="st-fadein">

          <div style={{ marginBottom: '24px' }}>
            <h1 style={{ fontSize: '22px', fontWeight: 800, color: '#0F172A', letterSpacing: '-0.02em', marginBottom: '5px' }}>Hardware Setup</h1>
            <p style={{ fontSize: '14px', color: '#64748B' }}>Select and test your camera and microphone before proceeding.</p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            {/* Camera preview */}
            <div style={{ aspectRatio: '4/3', position: 'relative', borderRadius: '12px', overflow: 'hidden', border: '1.5px solid #CBD5E1', boxShadow: '0 1px 4px rgba(15,23,42,0.08)', background: '#0F172A', lineHeight: 0 }}>
                <video
                  ref={videoRef}
                  autoPlay playsInline muted
                  style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', display: 'block', transform: 'scaleX(-1)' }}
                />
                {!stream && (
                  <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Loader2 style={{ width: '28px', height: '28px', color: '#475569', animation: 'spin 1s linear infinite' }} />
                  </div>
                )}
                {/* Camera label */}
                <div style={{ position: 'absolute', bottom: '10px', left: '10px', background: 'rgba(0,0,0,0.6)', padding: '3px 8px', borderRadius: '4px' }}>
                  <span style={{ fontSize: '10px', fontWeight: 700, color: '#57CC99', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Preview</span>
                </div>
            </div>

            {/* Controls */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

              {/* Camera selector */}
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '7px', fontSize: '13px', fontWeight: 700, color: '#475569', marginBottom: '8px' }}>
                  <Camera style={{ width: '14px', height: '14px', color: '#22577A' }} /> Select Camera
                </label>
                <select
                  value={selectedCam}
                  onChange={e => setSelectedCam(e.target.value)}
                  className="st-select"
                >
                  {devices.cameras.map(cam => (
                    <option key={cam.deviceId} value={cam.deviceId}>
                      {cam.label || `Camera ${cam.deviceId.slice(0, 5)}…`}
                    </option>
                  ))}
                </select>
              </div>

              {/* Microphone selector */}
              <div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '7px', fontSize: '13px', fontWeight: 700, color: '#475569', marginBottom: '8px' }}>
                  <Mic style={{ width: '14px', height: '14px', color: '#22577A' }} /> Select Microphone
                </label>
                <select
                  value={selectedMic}
                  onChange={e => setSelectedMic(e.target.value)}
                  className="st-select"
                  style={{ marginBottom: '12px' }}
                >
                  {devices.mics.map(mic => (
                    <option key={mic.deviceId} value={mic.deviceId}>
                      {mic.label || `Microphone ${mic.deviceId.slice(0, 5)}…`}
                    </option>
                  ))}
                </select>

                {/* Audio level bar */}
                <div style={{ background: '#fff', border: '1.5px solid #E2E8F0', borderRadius: '10px', padding: '14px 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: '#64748B' }}>Microphone Input</span>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: '#22577A' }}>{audioLevel}%</span>
                  </div>
                  <div style={{ height: '8px', background: '#F1F5F9', borderRadius: '4px', overflow: 'hidden', border: '1px solid #E2E8F0' }}>
                    <div style={{
                      height: '100%', borderRadius: '4px',
                      width: `${audioLevel}%`,
                      background: micBarColor,
                      transition: 'width 75ms ease, background 200ms ease',
                    }} />
                  </div>
                  <p style={{ fontSize: '11.5px', color: '#94A3B8', marginTop: '7px' }}>
                    {audioLevel === 0
                      ? 'No input detected — speak to test'
                      : audioLevel > 75
                      ? 'Volume too high — move away or lower mic gain'
                      : 'Microphone working correctly'}
                  </p>
                </div>
              </div>

              <button
                onClick={handleNext}
                disabled={!selectedCam || !selectedMic}
                className="st-btn st-btn-lg"
                style={{ width: '100%', marginTop: 'auto' }}
              >
                Confirm & Proceed <ArrowRight style={{ width: '16px', height: '16px' }} />
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
