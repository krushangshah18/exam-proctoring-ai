/**
 * Ensures a UTC ISO string is parsed correctly (adds 'Z' if no tz info present),
 * then formats it in the user's local timezone.
 */
export function parseUTC(iso: string): Date {
  if (!iso) return new Date(NaN);
  // Already has timezone info
  if (iso.endsWith('Z') || iso.includes('+') || /\d{2}:\d{2}$/.test(iso) === false) {
    return new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
  }
  return new Date(iso + 'Z');
}

const DATE_OPTS: Intl.DateTimeFormatOptions = {
  day: 'numeric', month: 'short', year: 'numeric',
};
const TIME_OPTS: Intl.DateTimeFormatOptions = {
  hour: '2-digit', minute: '2-digit', hour12: true,
};
const DATETIME_OPTS: Intl.DateTimeFormatOptions = {
  ...DATE_OPTS, ...TIME_OPTS,
};

/** "Jan 5, 2025" in user's local timezone */
export function fmtDate(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, DATE_OPTS);
}

/** "02:30 PM" in user's local timezone */
export function fmtTime(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString(undefined, TIME_OPTS);
}

/** "Jan 5, 2025, 02:30 PM" in user's local timezone */
export function fmtDateTime(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, DATETIME_OPTS);
}
