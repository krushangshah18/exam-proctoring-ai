/**
 * Ensures a UTC ISO string is parsed correctly (adds 'Z' if no tz info present),
 * then converts it to the user's local timezone for display.
 */
export function parseUTC(iso: string): Date {
  if (!iso) return new Date(NaN);
  // Already has timezone info (ends with Z or contains +/- offset)
  if (iso.endsWith('Z') || iso.includes('+') || /\d{2}:\d{2}$/.test(iso) === false) {
    return new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z');
  }
  return new Date(iso + 'Z');
}

/** Returns the user's browser timezone abbreviation, e.g. "IST", "EST", "GMT+5:30" */
export function getTZLabel(): string {
  try {
    return (
      Intl.DateTimeFormat(undefined, { timeZoneName: 'short' })
        .formatToParts(new Date())
        .find((p) => p.type === 'timeZoneName')?.value ?? ''
    );
  } catch {
    return '';
  }
}

// ─── Format options ───────────────────────────────────────────────────────────

const DATE_OPTS: Intl.DateTimeFormatOptions = {
  day: 'numeric', month: 'short', year: 'numeric',
};
const TIME_OPTS: Intl.DateTimeFormatOptions = {
  hour: '2-digit', minute: '2-digit', hour12: true,
};
const TIME_TZ_OPTS: Intl.DateTimeFormatOptions = {
  hour: '2-digit', minute: '2-digit', hour12: true, timeZoneName: 'short',
};
const DATETIME_OPTS: Intl.DateTimeFormatOptions = {
  ...DATE_OPTS, ...TIME_OPTS,
};
const DATETIME_TZ_OPTS: Intl.DateTimeFormatOptions = {
  ...DATE_OPTS, ...TIME_TZ_OPTS,
};
const IST_DATE_OPTS: Intl.DateTimeFormatOptions = {
  day: 'numeric', month: 'numeric', year: 'numeric', timeZone: 'Asia/Kolkata',
};
const IST_DATETIME_OPTS: Intl.DateTimeFormatOptions = {
  hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true, timeZone: 'Asia/Kolkata',
};

// ─── Without timezone label (use for compact/secondary displays) ──────────────

/** "Jan 5, 2025" in user's local timezone */
export function fmtDate(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, DATE_OPTS);
}

/** "02:30 PM" in user's local timezone (no label) */
export function fmtTime(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString(undefined, TIME_OPTS);
}

/** "Jan 5, 2025, 02:30 PM" in user's local timezone (no label) */
export function fmtDateTime(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, DATETIME_OPTS);
}

// ─── With timezone label (use wherever time is shown to students/admins) ──────

/** "02:30 PM IST" — time with browser timezone abbreviation */
export function fmtTimeTZ(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleTimeString(undefined, TIME_TZ_OPTS);
}

/** "Jan 5, 2025, 02:30 PM IST" — full datetime with timezone abbreviation */
export function fmtDateTimeTZ(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, DATETIME_TZ_OPTS);
}

/** Same as fmtDateTimeTZ but works from a Date object (for computed times) */
export function fmtDateTimeTZFromDate(d: Date): string {
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString(undefined, DATETIME_TZ_OPTS);
}

/** "31/3/2026, 11:03:28 AM IST" — always displayed in India Standard Time */
export function fmtDateTimeIST(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  const date = d.toLocaleDateString('en-IN', IST_DATE_OPTS);
  const time = d.toLocaleTimeString('en-IN', IST_DATETIME_OPTS);
  return `${date}, ${time} IST`;
}

/** "11:03:28 AM IST" — always displayed in India Standard Time */
export function fmtTimeIST(iso: string): string {
  const d = parseUTC(iso);
  if (isNaN(d.getTime())) return '—';
  return `${d.toLocaleTimeString('en-IN', IST_DATETIME_OPTS)} IST`;
}
