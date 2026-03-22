"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Home } from "lucide-react";
import React from "react";

export function Breadcrumbs() {
  const pathname = usePathname();
  const segments = pathname.split("/").filter(Boolean);

  if (segments.length === 0) return null;

  return (
    <nav className="flex items-center text-sm text-muted-foreground whitespace-nowrap overflow-x-auto pb-2">
      <Link href="/sys/dashboard" className="hover:text-foreground transition-colors flex items-center">
        <Home className="h-4 w-4" />
      </Link>
      
      {segments.map((segment, index) => {
        const isLast = index === segments.length - 1;
        const href = `/${segments.slice(0, index + 1).join("/")}`;
        const title = segment.charAt(0).toUpperCase() + segment.slice(1).replace(/-/g, " ");

        return (
          <React.Fragment key={href}>
            <ChevronRight className="h-4 w-4 mx-1 flex-shrink-0" />
            {isLast ? (
              <span className="font-medium text-foreground" aria-current="page">
                {title}
              </span>
            ) : (
              <Link href={href} className="hover:text-foreground transition-colors">
                {title}
              </Link>
            )}
          </React.Fragment>
        );
      })}
    </nav>
  );
}
