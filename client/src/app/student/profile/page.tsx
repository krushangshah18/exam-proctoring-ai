"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import RoleGuard from "@/components/auth/role-guard";
import Webcam from "react-webcam";
import {
  Camera,
  User,
  Lock,
  Loader2,
  RefreshCw,
  CheckCircle2,
  X,
  Mail,
  Shield,
  Eye,
  EyeOff,
  GraduationCap,
} from "lucide-react";
import api from "@/lib/axios";
import { toast } from "sonner";
import { StudentPageShell } from "@/components/student/StudentShell";

/* ── helpers ────────────────────────────────────────────────────────────── */
function getInitials(name?: string) {
  if (!name) return "S";
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

/* ── sub-components ─────────────────────────────────────────────────────── */
function FieldGroup({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div style={{ marginBottom: "20px" }}>
      <label
        style={{
          display: "block",
          fontSize: "12.5px",
          fontWeight: 700,
          color: "#475569",
          marginBottom: "7px",
          letterSpacing: "0.01em",
        }}
      >
        {label}
      </label>
      {children}
      {hint && (
        <p
          style={{
            fontSize: "11.5px",
            color: "#64748B",
            marginTop: "5px",
            fontWeight: 500,
            lineHeight: 1.5,
          }}
        >
          {hint}
        </p>
      )}
    </div>
  );
}

function SectionHeader({
  icon,
  title,
  subtitle,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        marginBottom: "22px",
        paddingBottom: "16px",
        borderBottom: "1.5px solid #F1F5F9",
      }}
    >
      <div
        style={{
          width: "36px",
          height: "36px",
          borderRadius: "10px",
          background: "rgba(34,87,122,0.08)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
        }}
      >
        {icon}
      </div>
      <div>
        <h3
          style={{
            fontSize: "14.5px",
            fontWeight: 800,
            color: "#0F172A",
            letterSpacing: "-0.01em",
          }}
        >
          {title}
        </h3>
        <p
          style={{
            fontSize: "12px",
            color: "#64748B",
            marginTop: "1px",
            fontWeight: 500,
          }}
        >
          {subtitle}
        </p>
      </div>
    </div>
  );
}

/* ── main ────────────────────────────────────────────────────────────────── */
export default function StudentProfile() {
  const webcamRef = useRef<Webcam>(null);

  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [showWebcam, setShowWebcam] = useState(false);
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [fullName, setFullName] = useState("");
  const [showOld, setShowOld] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [passwordData, setPasswordData] = useState({
    old_password: "",
    new_password: "",
    confirm_password: "",
  });

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const res = await api.get("/auth/me");
      setUser(res.data);
      setFullName(res.data.full_name || "");
    } catch {
      toast.error("Failed to load profile");
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateProfile = async () => {
    if (!fullName.trim()) {
      toast.error("Full name cannot be empty");
      return;
    }
    setUpdating(true);
    try {
      await api.put("/auth/me/profile", { full_name: fullName });
      toast.success("Profile updated successfully");
      fetchUserProfile();
    } catch (e: any) {
      toast.error(e.response?.data?.detail || "Failed to update profile");
    } finally {
      setUpdating(false);
    }
  };

  const handleChangePassword = async () => {
    if (!passwordData.old_password || !passwordData.new_password) {
      toast.error("Please fill in all password fields");
      return;
    }
    if (passwordData.new_password !== passwordData.confirm_password) {
      toast.error("New passwords do not match");
      return;
    }
    if (passwordData.new_password.length < 8) {
      toast.error("Password must be at least 8 characters");
      return;
    }
    setUpdating(true);
    try {
      await api.post("/auth/change-password", {
        old_password: passwordData.old_password,
        new_password: passwordData.new_password,
      });
      toast.success("Password changed successfully");
      setPasswordData({
        old_password: "",
        new_password: "",
        confirm_password: "",
      });
    } catch (e: any) {
      toast.error(e.response?.data?.detail || "Failed to change password");
    } finally {
      setUpdating(false);
    }
  };

  const capture = useCallback(() => {
    const src = webcamRef.current?.getScreenshot();
    if (src) setImgSrc(src);
  }, []);

  const handleProfileImageUpload = async () => {
    if (!imgSrc) {
      toast.error("Please capture a selfie first");
      return;
    }
    setUpdating(true);
    try {
      const res = await fetch(imgSrc);
      const blob = await res.blob();
      const file = new File([blob], "selfie.jpg", { type: "image/jpeg" });
      const formData = new FormData();
      formData.append("selfie", file);
      await api.put("/auth/me/profile-image", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      toast.success("Profile image updated successfully");
      setShowWebcam(false);
      setImgSrc(null);
      fetchUserProfile();
    } catch (e: any) {
      toast.error(e.response?.data?.detail || "Failed to update profile image");
    } finally {
      setUpdating(false);
    }
  };

  const initials = getInitials(user?.full_name);
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  /* ── input style ──────────────────────────────────────────────────────── */
  const inputStyle: React.CSSProperties = {
    width: "100%",
    padding: "10px 14px",
    border: "1.5px solid #E2E8F0",
    borderRadius: "9px",
    fontSize: "13.5px",
    fontWeight: 500,
    color: "#0F172A",
    background: "#FAFCFF",
    outline: "none",
    fontFamily: "'Plus Jakarta Sans', sans-serif",
    transition: "border-color 150ms, box-shadow 150ms",
    boxSizing: "border-box",
  };

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          height: "100vh",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Loader2
          style={{
            width: "28px",
            height: "28px",
            color: "#22577A",
            animation: "spin 1s linear infinite",
          }}
        />
        <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
      </div>
    );
  }

  return (
    <RoleGuard allowedRoles={["STUDENT"]}>
      <StudentPageShell
        backHref="/student/dashboard"
        backLabel="Back to Dashboard"
      >
        <style>{`
          @keyframes spin{to{transform:rotate(360deg)}}
          @keyframes fadein{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
          .pf-input:focus{border-color:#38A3A5 !important; box-shadow:0 0 0 3px rgba(56,163,165,0.1) !important;}
          .pf-input:disabled{background:#F8FAFC !important; color:#64748B !important; cursor:not-allowed;}
          .pf-input::placeholder{color:#64748B;}
          .pf-card{background:#fff;border:1.5px solid #E2E8F0;border-radius:16px;padding:26px;box-shadow:0 1px 4px rgba(15,23,42,0.05);}
        `}</style>

        <div
          style={{
            width: "100%",
            maxWidth: "900px",
            margin: "0 auto",
            animation: "fadein 0.4s ease both",
          }}
        >
          {/* ── HERO BANNER CARD ──────────────────────────────────────────── */}
          <div
            style={{
              borderRadius: "20px",
              overflow: "hidden",
              border: "1.5px solid #E2E8F0",
              boxShadow: "0 4px 20px rgba(34,87,122,0.1)",
              marginBottom: "24px",
            }}
          >
            {/* Gradient banner */}
            <div
              style={{
                height: "110px",
                background:
                  "linear-gradient(135deg, #22577A 0%, #38A3A5 60%, #57CC99 100%)",
                position: "relative",
                overflow: "hidden",
              }}
            >
              {/* Subtle dot grid */}
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  backgroundImage:
                    "radial-gradient(circle, rgba(255,255,255,0.12) 1px, transparent 1px)",
                  backgroundSize: "20px 20px",
                }}
              />
              {/* Decorative circles */}
              <div
                style={{
                  position: "absolute",
                  right: "-30px",
                  top: "-30px",
                  width: "140px",
                  height: "140px",
                  borderRadius: "50%",
                  background: "rgba(255,255,255,0.07)",
                }}
              />
              <div
                style={{
                  position: "absolute",
                  right: "60px",
                  bottom: "-40px",
                  width: "100px",
                  height: "100px",
                  borderRadius: "50%",
                  background: "rgba(255,255,255,0.06)",
                }}
              />
            </div>

            {/* Profile info row — overlaps banner */}
            <div style={{ background: "#fff", padding: "0 28px 22px" }}>
              <div
                style={{
                  display: "flex",
                  alignItems: "flex-end",
                  justifyContent: "space-between",
                  marginTop: "-36px",
                  flexWrap: "wrap",
                  gap: "16px",
                }}
              >
                {/* Avatar + name */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "flex-end",
                    gap: "16px",
                    flex: 1,
                    minWidth: "280px",
                  }}
                >
                  {/* Avatar */}
                  <div
                    style={{
                      width: "80px",
                      height: "80px",
                      borderRadius: "50%",
                      flexShrink: 0,
                      border: "4px solid #fff",
                      overflow: "hidden",
                      position: "relative",
                      boxShadow: "0 4px 14px rgba(34,87,122,0.2)",
                      background: "#22577A",
                    }}
                  >
                    {user?.profile_image_url ? (
                      <img
                        src={user.profile_image_url}
                        alt="Profile"
                        style={{
                          width: "100%",
                          height: "100%",
                          objectFit: "cover",
                        }}
                        onError={(e) => {
                          (e.currentTarget as HTMLElement).style.display =
                            "none";
                        }}
                      />
                    ) : (
                      <div
                        style={{
                          width: "100%",
                          height: "100%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "24px",
                          fontWeight: 800,
                          color: "#fff",
                        }}
                      >
                        {initials}
                      </div>
                    )}
                  </div>

                  {/* Name + email — shown below banner */}
                  <div style={{ paddingBottom: "4px", textAlign: "left" }}>
                    <h2
                      style={{
                        fontSize: "18px",
                        fontWeight: 800,
                        color: "#0F172A",
                        letterSpacing: "-0.02em",
                        lineHeight: 1.2,
                      }}
                    >
                      {user?.full_name || "Student"}
                    </h2>
                    <p
                      style={{
                        fontSize: "13px",
                        color: "#64748B",
                        fontWeight: 500,
                        marginTop: "3px",
                        display: "flex",
                        alignItems: "center",
                        gap: "5px",
                      }}
                    >
                      <Mail style={{ width: "12px", height: "12px" }} />
                      {user?.email}
                    </p>
                  </div>
                </div>

                {/* Update photo button */}
                <button
                  onClick={() => setShowWebcam(true)}
                  disabled={updating}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "7px",
                    padding: "9px 16px",
                    borderRadius: "9px",
                    cursor: "pointer",
                    background: "rgba(34,87,122,0.07)",
                    border: "1.5px solid rgba(34,87,122,0.18)",
                    color: "#22577A",
                    fontSize: "13px",
                    fontWeight: 700,
                    fontFamily: "'Plus Jakarta Sans', sans-serif",
                    transition: "all 150ms",
                    flexShrink: 0,
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLElement).style.background =
                      "rgba(34,87,122,0.12)";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.background =
                      "rgba(34,87,122,0.07)";
                  }}
                >
                  <Camera style={{ width: "14px", height: "14px" }} />
                  Update Photo
                </button>
              </div>

              {/* Role badge */}
              <div
                style={{
                  marginTop: "14px",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  flexWrap: "wrap",
                }}
              >
                <GraduationCap
                  style={{ width: "13px", height: "13px", color: "#38A3A5" }}
                />
                <span
                  style={{
                    fontSize: "12px",
                    fontWeight: 600,
                    color: "#38A3A5",
                  }}
                >
                  Student Account
                </span>
                <span
                  style={{
                    width: "4px",
                    height: "4px",
                    borderRadius: "50%",
                    background: "#CBD5E1",
                    display: "inline-block",
                    margin: "0 4px",
                  }}
                />
                <Shield
                  style={{ width: "12px", height: "12px", color: "#64748B" }}
                />
                <span
                  style={{
                    fontSize: "12px",
                    fontWeight: 500,
                    color: "#64748B",
                  }}
                >
                  Verified Identity
                </span>
              </div>
            </div>
          </div>

          {/* ── TWO-COLUMN GRID ───────────────────────────────────────────── */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "20px",
              alignItems: "start",
            }}
          >
            {/* Left — Basic Information */}
            <div className="pf-card">
              <SectionHeader
                icon={
                  <User
                    style={{ width: "16px", height: "16px", color: "#22577A" }}
                  />
                }
                title="Basic Information"
                subtitle="Update your name and account details"
              />

              <FieldGroup
                label="Email Address"
                hint="Email cannot be changed after registration"
              >
                <div style={{ position: "relative" }}>
                  <input
                    type="email"
                    value={user?.email || ""}
                    disabled
                    className="pf-input"
                    style={{ ...inputStyle, paddingRight: "38px" }}
                  />
                  <Lock
                    style={{
                      position: "absolute",
                      right: "12px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      width: "13px",
                      height: "13px",
                      color: "#64748B",
                    }}
                  />
                </div>
              </FieldGroup>

              <FieldGroup label="Full Name">
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Enter your full name"
                  className="pf-input"
                  style={inputStyle}
                  onFocus={(e) => {
                    e.currentTarget.style.borderColor = "#38A3A5";
                    e.currentTarget.style.boxShadow =
                      "0 0 0 3px rgba(56,163,165,0.1)";
                  }}
                  onBlur={(e) => {
                    e.currentTarget.style.borderColor = "#E2E8F0";
                    e.currentTarget.style.boxShadow = "none";
                  }}
                />
              </FieldGroup>

              <button
                onClick={handleUpdateProfile}
                disabled={updating}
                style={{
                  width: "100%",
                  padding: "11px",
                  borderRadius: "9px",
                  border: "none",
                  cursor: updating ? "not-allowed" : "pointer",
                  background: updating ? "#64748B" : "#22577A",
                  color: "#fff",
                  fontSize: "13.5px",
                  fontWeight: 700,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "7px",
                  fontFamily: "'Plus Jakarta Sans', sans-serif",
                  transition: "background 150ms",
                  marginTop: "4px",
                }}
                onMouseEnter={(e) => {
                  if (!updating)
                    (e.currentTarget as HTMLElement).style.background =
                      "#2C6A91";
                }}
                onMouseLeave={(e) => {
                  if (!updating)
                    (e.currentTarget as HTMLElement).style.background =
                      "#22577A";
                }}
              >
                {updating ? (
                  <>
                    <Loader2
                      style={{
                        width: "14px",
                        height: "14px",
                        animation: "spin 1s linear infinite",
                      }}
                    />{" "}
                    Saving…
                  </>
                ) : (
                  <>
                    <CheckCircle2 style={{ width: "14px", height: "14px" }} />{" "}
                    Save Changes
                  </>
                )}
              </button>
            </div>

            {/* Right — Change Password */}
            <div className="pf-card">
              <SectionHeader
                icon={
                  <Lock
                    style={{ width: "16px", height: "16px", color: "#22577A" }}
                  />
                }
                title="Change Password"
                subtitle="Keep your account secure with a strong password"
              />

              <FieldGroup label="Current Password">
                <div style={{ position: "relative" }}>
                  <input
                    type={showOld ? "text" : "password"}
                    value={passwordData.old_password}
                    onChange={(e) =>
                      setPasswordData({
                        ...passwordData,
                        old_password: e.target.value,
                      })
                    }
                    placeholder="Enter current password"
                    className="pf-input"
                    style={{ ...inputStyle, paddingRight: "38px" }}
                    onFocus={(e) => {
                      e.currentTarget.style.borderColor = "#38A3A5";
                      e.currentTarget.style.boxShadow =
                        "0 0 0 3px rgba(56,163,165,0.1)";
                    }}
                    onBlur={(e) => {
                      e.currentTarget.style.borderColor = "#E2E8F0";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  />
                  <button
                    onClick={() => setShowOld((v) => !v)}
                    tabIndex={-1}
                    style={{
                      position: "absolute",
                      right: "11px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      color: "#64748B",
                      padding: "2px",
                    }}
                  >
                    {showOld ? (
                      <EyeOff style={{ width: "14px", height: "14px" }} />
                    ) : (
                      <Eye style={{ width: "14px", height: "14px" }} />
                    )}
                  </button>
                </div>
              </FieldGroup>

              <div
                style={{
                  height: "1px",
                  background: "#F1F5F9",
                  margin: "4px 0 20px",
                }}
              />

              <FieldGroup label="New Password" hint="Minimum 8 characters">
                <div style={{ position: "relative" }}>
                  <input
                    type={showNew ? "text" : "password"}
                    value={passwordData.new_password}
                    onChange={(e) =>
                      setPasswordData({
                        ...passwordData,
                        new_password: e.target.value,
                      })
                    }
                    placeholder="At least 8 characters"
                    className="pf-input"
                    style={{ ...inputStyle, paddingRight: "38px" }}
                    onFocus={(e) => {
                      e.currentTarget.style.borderColor = "#38A3A5";
                      e.currentTarget.style.boxShadow =
                        "0 0 0 3px rgba(56,163,165,0.1)";
                    }}
                    onBlur={(e) => {
                      e.currentTarget.style.borderColor = "#E2E8F0";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  />
                  <button
                    onClick={() => setShowNew((v) => !v)}
                    tabIndex={-1}
                    style={{
                      position: "absolute",
                      right: "11px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      color: "#64748B",
                      padding: "2px",
                    }}
                  >
                    {showNew ? (
                      <EyeOff style={{ width: "14px", height: "14px" }} />
                    ) : (
                      <Eye style={{ width: "14px", height: "14px" }} />
                    )}
                  </button>
                </div>
              </FieldGroup>

              <FieldGroup label="Confirm New Password">
                <div style={{ position: "relative" }}>
                  <input
                    type={showConfirm ? "text" : "password"}
                    value={passwordData.confirm_password}
                    onChange={(e) =>
                      setPasswordData({
                        ...passwordData,
                        confirm_password: e.target.value,
                      })
                    }
                    placeholder="Repeat new password"
                    className="pf-input"
                    style={{
                      ...inputStyle,
                      paddingRight: "38px",
                      borderColor:
                        passwordData.confirm_password &&
                        passwordData.confirm_password !==
                          passwordData.new_password
                          ? "rgba(239,68,68,0.5)"
                          : undefined,
                    }}
                    onFocus={(e) => {
                      e.currentTarget.style.borderColor = "#38A3A5";
                      e.currentTarget.style.boxShadow =
                        "0 0 0 3px rgba(56,163,165,0.1)";
                    }}
                    onBlur={(e) => {
                      const mismatch =
                        passwordData.confirm_password &&
                        passwordData.confirm_password !==
                          passwordData.new_password;
                      e.currentTarget.style.borderColor = mismatch
                        ? "rgba(239,68,68,0.5)"
                        : "#E2E8F0";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  />
                  <button
                    onClick={() => setShowConfirm((v) => !v)}
                    tabIndex={-1}
                    style={{
                      position: "absolute",
                      right: "11px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      background: "none",
                      border: "none",
                      cursor: "pointer",
                      color: "#64748B",
                      padding: "2px",
                    }}
                  >
                    {showConfirm ? (
                      <EyeOff style={{ width: "14px", height: "14px" }} />
                    ) : (
                      <Eye style={{ width: "14px", height: "14px" }} />
                    )}
                  </button>
                </div>
                {passwordData.confirm_password &&
                  passwordData.confirm_password !==
                    passwordData.new_password && (
                    <p
                      style={{
                        fontSize: "11.5px",
                        color: "#EF4444",
                        marginTop: "4px",
                        fontWeight: 600,
                      }}
                    >
                      Passwords do not match
                    </p>
                  )}
              </FieldGroup>

              <button
                onClick={handleChangePassword}
                disabled={updating}
                style={{
                  width: "100%",
                  padding: "11px",
                  borderRadius: "9px",
                  border: "none",
                  cursor: updating ? "not-allowed" : "pointer",
                  background: updating ? "#64748B" : "#0F172A",
                  color: "#fff",
                  fontSize: "13.5px",
                  fontWeight: 700,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "7px",
                  fontFamily: "'Plus Jakarta Sans', sans-serif",
                  transition: "background 150ms",
                  marginTop: "4px",
                }}
                onMouseEnter={(e) => {
                  if (!updating)
                    (e.currentTarget as HTMLElement).style.background =
                      "#1E293B";
                }}
                onMouseLeave={(e) => {
                  if (!updating)
                    (e.currentTarget as HTMLElement).style.background =
                      "#0F172A";
                }}
              >
                {updating ? (
                  <>
                    <Loader2
                      style={{
                        width: "14px",
                        height: "14px",
                        animation: "spin 1s linear infinite",
                      }}
                    />{" "}
                    Updating…
                  </>
                ) : (
                  <>
                    <Lock style={{ width: "14px", height: "14px" }} /> Update
                    Password
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* ── WEBCAM MODAL ──────────────────────────────────────────────────── */}
        {showWebcam && (
          <div
            style={{
              position: "fixed",
              inset: 0,
              zIndex: 200,
              background: "rgba(15,23,42,0.65)",
              backdropFilter: "blur(8px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "24px",
            }}
          >
            <div
              style={{
                background: "#fff",
                borderRadius: "20px",
                width: "100%",
                maxWidth: "440px",
                boxShadow: "0 32px 80px rgba(15,23,42,0.25)",
                border: "1.5px solid #E2E8F0",
                overflow: "hidden",
                animation: "fadein 0.25s ease both",
              }}
            >
              {/* Modal header */}
              <div
                style={{
                  padding: "18px 22px",
                  borderBottom: "1.5px solid #F1F5F9",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  background: "#FAFCFF",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: "10px" }}
                >
                  <div
                    style={{
                      width: "32px",
                      height: "32px",
                      borderRadius: "8px",
                      background: "rgba(34,87,122,0.08)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <Camera
                      style={{
                        width: "15px",
                        height: "15px",
                        color: "#22577A",
                      }}
                    />
                  </div>
                  <div>
                    <h3
                      style={{
                        fontSize: "14.5px",
                        fontWeight: 800,
                        color: "#0F172A",
                        letterSpacing: "-0.01em",
                      }}
                    >
                      Capture Selfie
                    </h3>
                    <p
                      style={{
                        fontSize: "12px",
                        color: "#64748B",
                        fontWeight: 500,
                        marginTop: "1px",
                      }}
                    >
                      Used for exam face verification
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => {
                    setShowWebcam(false);
                    setImgSrc(null);
                  }}
                  style={{
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    padding: "6px",
                    borderRadius: "8px",
                    color: "#64748B",
                    display: "flex",
                    transition: "background 150ms",
                  }}
                  onMouseEnter={(e) => {
                    (e.currentTarget as HTMLElement).style.background =
                      "#F1F5F9";
                  }}
                  onMouseLeave={(e) => {
                    (e.currentTarget as HTMLElement).style.background = "none";
                  }}
                >
                  <X style={{ width: "18px", height: "18px" }} />
                </button>
              </div>

              {/* Webcam / preview */}
              <div style={{ padding: "20px 22px" }}>
                <div
                  style={{
                    borderRadius: "12px",
                    overflow: "hidden",
                    border: "2px solid #E2E8F0",
                    background: "#0F172A",
                    aspectRatio: "4/3",
                    marginBottom: "16px",
                    position: "relative",
                  }}
                >
                  {!imgSrc ? (
                    <Webcam
                      audio={false}
                      ref={webcamRef}
                      screenshotFormat="image/jpeg"
                      videoConstraints={{ facingMode: "user" }}
                      style={{
                        width: "100%",
                        height: "100%",
                        objectFit: "cover",
                        display: "block",
                      }}
                    />
                  ) : (
                    <>
                      <img
                        src={imgSrc}
                        alt="Selfie"
                        style={{
                          width: "100%",
                          height: "100%",
                          objectFit: "cover",
                          display: "block",
                        }}
                      />
                      <div
                        style={{
                          position: "absolute",
                          top: "10px",
                          right: "10px",
                          background: "rgba(34,197,94,0.9)",
                          padding: "3px 10px",
                          borderRadius: "20px",
                          display: "flex",
                          alignItems: "center",
                          gap: "5px",
                        }}
                      >
                        <CheckCircle2
                          style={{
                            width: "11px",
                            height: "11px",
                            color: "#fff",
                          }}
                        />
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            color: "#fff",
                          }}
                        >
                          Photo Captured
                        </span>
                      </div>
                    </>
                  )}
                </div>

                {/* Capture / retake */}
                <div
                  style={{
                    display: "flex",
                    justifyContent: "center",
                    marginBottom: "14px",
                  }}
                >
                  {!imgSrc ? (
                    <button
                      onClick={capture}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "7px",
                        padding: "9px 20px",
                        borderRadius: "9px",
                        border: "1.5px solid #E2E8F0",
                        background: "#fff",
                        color: "#22577A",
                        fontSize: "13px",
                        fontWeight: 700,
                        cursor: "pointer",
                        fontFamily: "'Plus Jakarta Sans', sans-serif",
                        transition: "all 150ms",
                      }}
                      onMouseEnter={(e) => {
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "#38A3A5";
                        (e.currentTarget as HTMLElement).style.background =
                          "#F0FDFC";
                      }}
                      onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.borderColor =
                          "#E2E8F0";
                        (e.currentTarget as HTMLElement).style.background =
                          "#fff";
                      }}
                    >
                      <Camera style={{ width: "14px", height: "14px" }} /> Take
                      Photo
                    </button>
                  ) : (
                    <button
                      onClick={() => setImgSrc(null)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "7px",
                        padding: "9px 20px",
                        borderRadius: "9px",
                        border: "1.5px solid #E2E8F0",
                        background: "#fff",
                        color: "#64748B",
                        fontSize: "13px",
                        fontWeight: 700,
                        cursor: "pointer",
                        fontFamily: "'Plus Jakarta Sans', sans-serif",
                      }}
                    >
                      <RefreshCw style={{ width: "13px", height: "13px" }} />{" "}
                      Retake
                    </button>
                  )}
                </div>

                {/* Footer buttons */}
                <div style={{ display: "flex", gap: "10px" }}>
                  <button
                    onClick={() => {
                      setShowWebcam(false);
                      setImgSrc(null);
                    }}
                    style={{
                      flex: 1,
                      padding: "11px",
                      borderRadius: "9px",
                      border: "1.5px solid #E2E8F0",
                      background: "#fff",
                      color: "#475569",
                      fontSize: "13px",
                      fontWeight: 700,
                      cursor: "pointer",
                      fontFamily: "'Plus Jakarta Sans', sans-serif",
                      transition: "all 150ms",
                    }}
                    onMouseEnter={(e) => {
                      (e.currentTarget as HTMLElement).style.background =
                        "#F8FAFC";
                    }}
                    onMouseLeave={(e) => {
                      (e.currentTarget as HTMLElement).style.background =
                        "#fff";
                    }}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleProfileImageUpload}
                    disabled={!imgSrc || updating}
                    style={{
                      flex: 1,
                      padding: "11px",
                      borderRadius: "9px",
                      border: "none",
                      background: !imgSrc || updating ? "#64748B" : "#22577A",
                      color: "#fff",
                      fontSize: "13px",
                      fontWeight: 700,
                      cursor: !imgSrc || updating ? "not-allowed" : "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "7px",
                      fontFamily: "'Plus Jakarta Sans', sans-serif",
                      transition: "background 150ms",
                    }}
                    onMouseEnter={(e) => {
                      if (imgSrc && !updating)
                        (e.currentTarget as HTMLElement).style.background =
                          "#2C6A91";
                    }}
                    onMouseLeave={(e) => {
                      if (imgSrc && !updating)
                        (e.currentTarget as HTMLElement).style.background =
                          "#22577A";
                    }}
                  >
                    {updating ? (
                      <>
                        <Loader2
                          style={{
                            width: "14px",
                            height: "14px",
                            animation: "spin 1s linear infinite",
                          }}
                        />{" "}
                        Uploading…
                      </>
                    ) : (
                      <>
                        <CheckCircle2
                          style={{ width: "14px", height: "14px" }}
                        />{" "}
                        Save Photo
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </StudentPageShell>
    </RoleGuard>
  );
}
