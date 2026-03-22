import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface StatusBadgeProps {
  status: string;
  className?: string;
}

const statusStyles: Record<string, string> = {
  PENDING: "bg-yellow-100 text-yellow-800 hover:bg-yellow-100/80 border-yellow-200",
  APPROVED: "bg-green-100 text-green-800 hover:bg-green-100/80 border-green-200",
  REJECTED: "bg-red-100 text-red-800 hover:bg-red-100/80 border-red-200",
  ACTIVE: "bg-blue-100 text-blue-800 hover:bg-blue-100/80 border-blue-200",
  WARNING: "bg-orange-100 text-orange-800 hover:bg-orange-100/80 border-orange-200",
  TERMINATED: "bg-gray-100 text-gray-800 hover:bg-gray-100/80 border-gray-200",
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const normalizedStatus = status?.toUpperCase() || "UNKNOWN";
  const style = statusStyles[normalizedStatus] || "bg-gray-100 text-gray-800 hover:bg-gray-100/80 border-gray-200";

  return (
    <Badge variant="outline" className={cn("px-2.5 py-0.5 font-medium whitespace-nowrap", style, className)}>
      {normalizedStatus}
    </Badge>
  );
}
