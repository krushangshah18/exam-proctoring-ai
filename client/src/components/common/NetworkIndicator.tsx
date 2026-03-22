"use client";

import { useState, useEffect } from "react";
import { WifiOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export function NetworkIndicator() {
  const [isOnline, setIsOnline] = useState(true);

  useEffect(() => {
    setIsOnline(navigator.onLine);

    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);

    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  if (isOnline) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 animate-in fade-in slide-in-from-bottom-4">
      <Badge 
        variant="destructive" 
        className={cn(
          "px-4 py-2 flex items-center gap-2 shadow-lg",
          "bg-red-500 hover:bg-red-600 text-white border-none"
        )}
      >
        <WifiOff className="h-4 w-4" />
        <span className="font-medium text-sm">You are offline</span>
      </Badge>
    </div>
  );
}
