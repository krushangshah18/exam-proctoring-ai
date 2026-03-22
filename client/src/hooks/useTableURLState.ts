import { useCallback, useMemo } from "react";
import { useRouter, usePathname, useSearchParams } from "next/navigation";

export function useTableURLState() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const getQueryString = useCallback(
    (name: string, value: string | null) => {
      // Lazy fetch the searchParams string inside the callback 
      // instead of putting `searchParams` in the useMemo dependency
      const currentSearchParamsStr = window.location.search;
      const params = new URLSearchParams(currentSearchParamsStr);
      if (value) {
        params.set(name, value);
      } else {
        params.delete(name);
      }
      return params.toString();
    },
    []
  );

  const setPage = useCallback((page: number) => {
    router.push(`${pathname}?${getQueryString("page", page.toString())}`);
  }, [router, pathname, getQueryString]);

  const setPageSize = useCallback((size: number) => {
    const params = new URLSearchParams(window.location.search);
    params.set("size", size.toString());
    params.set("page", "1");
    router.push(`${pathname}?${params.toString()}`);
  }, [router, pathname]);

  const setSearch = useCallback((search: string) => {
    const params = new URLSearchParams(window.location.search);
    if (search) {
      params.set("search", search);
    } else {
      params.delete("search");
    }
    params.set("page", "1");
    router.push(`${pathname}?${params.toString()}`);
  }, [router, pathname]);

  const setSorting = useCallback((sortBy: string, sortOrder: "asc" | "desc") => {
    const params = new URLSearchParams(window.location.search);
    params.set("sort_by", sortBy);
    params.set("sort_order", sortOrder);
    router.push(`${pathname}?${params.toString()}`);
  }, [router, pathname]);

  const clearSorting = useCallback(() => {
    const params = new URLSearchParams(window.location.search);
    params.delete("sort_by");
    params.delete("sort_order");
    router.push(`${pathname}?${params.toString()}`);
  }, [router, pathname]);

  return useMemo(() => ({
    page: Number(searchParams.get("page")) || 1,
    size: Number(searchParams.get("size")) || 10,
    search: searchParams.get("search") || "",
    sortBy: searchParams.get("sort_by") || "",
    sortOrder: (searchParams.get("sort_order") as "asc" | "desc") || "desc",
    setPage,
    setPageSize,
    setSearch,
    setSorting,
    clearSorting
  }), [searchParams, setPage, setPageSize, setSearch, setSorting, clearSorting]);
}
