import { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";

export default function ExamLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      {/* Locked down header */}
      <header className="bg-white border-b px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-2">
          <div className="bg-indigo-100 p-1.5 rounded-lg">
            <ShieldCheck className="h-5 w-5 text-indigo-700" />
          </div>
          <h1 className="text-lg font-bold tracking-tight text-slate-900 hidden sm:block">
            Proctor AI Secure Environment
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
          </span>
          <span className="text-sm font-semibold text-emerald-700 bg-emerald-50 px-3 py-1 rounded-full border border-emerald-200">
            Secure Connection
          </span>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col">
        {children}
      </main>
    </div>
  );
}
