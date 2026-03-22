"use client";

import { useEffect, useState, useRef } from "react";
import { Search, X, Loader2 } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

interface SearchInputProps {
  initialValue?: string;
  onSearch: (value: string) => void;
  isLoading?: boolean;
  placeholder?: string;
  debounceMs?: number;
}

export function SearchInput({
  initialValue = "",
  onSearch,
  isLoading = false,
  placeholder = "Search...",
  debounceMs = 500,
}: SearchInputProps) {
  const [value, setValue] = useState(initialValue);
  const isFirstRender = useRef(true);

  // Sync with external initialValue changes (eg: on mount from URL)
  useEffect(() => {
    setValue(initialValue);
  }, [initialValue]);

  // Debounced search trigger
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }

    const timer = setTimeout(() => {
      onSearch(value);
    }, debounceMs);

    return () => clearTimeout(timer);
  }, [value, debounceMs, onSearch]);

  const handleClear = () => {
    setValue("");
    onSearch(""); // clear immediately
  };

  return (
    <div className="relative w-full max-w-sm">
      <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none text-muted-foreground">
        {isLoading ? (
          <Loader2 className="h-4 w-4 animate-spin" />
        ) : (
          <Search className="h-4 w-4" />
        )}
      </div>
      <Input
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        className="pl-9 pr-9"
        aria-label="Search"
      />
      {value && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="absolute inset-y-0 right-0 h-full w-9 py-0 hover:bg-transparent"
          onClick={handleClear}
          aria-label="Clear search"
        >
          <X className="h-4 w-4 text-muted-foreground hover:text-foreground transition-colors" />
        </Button>
      )}
    </div>
  );
}
