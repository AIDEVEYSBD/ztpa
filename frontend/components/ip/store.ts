"use client";

/**
 * The address drawer's one piece of global state, and the reason it is global.
 *
 * The drill-down has to be openable from three unrelated places — a keystroke
 * anywhere in the console, any address chip in any panel, and an agent answer
 * that cites an address — none of which can reasonably own the drawer's markup
 * or sit inside a shared React subtree that does. A context provider would make
 * every one of those call sites depend on somebody remembering to wrap them.
 *
 * So the state lives in this module and is read through `useSyncExternalStore`:
 * `<IpLookup />` is mounted ONCE (the console shell), every other caller just
 * calls `useIpLookup().open("10.30.7.7")` — or the bare `openIpLookup()` from
 * outside React entirely — and nothing has to be threaded through props.
 *
 * `seq` is what makes "open the same address again" mean something: re-issuing
 * an identical query bumps it, and the fetch effect keys off it, so pressing
 * Enter twice re-asks the API instead of silently showing a stale answer.
 */

import { useCallback, useSyncExternalStore } from "react";
import { DEFAULT_IP_MODE, normaliseMode, type IpMode } from "./addr";

export interface IpQuery {
  address: string;
  mode: IpMode;
}

export interface IpLookupState {
  open: boolean;
  /** The query to run, or null when the drawer is open with an empty prompt. */
  query: IpQuery | null;
  /** Bumped on every issued query, including a re-issue of the same one. */
  seq: number;
  /** Most-recent-first, de-duplicated, in memory only. Deliberately NOT
   *  persisted: which addresses an operator investigated is a record of an
   *  investigation, and it is not this component's to write to a disk. */
  recent: IpQuery[];
}

const EMPTY: IpLookupState = Object.freeze({ open: false, query: null, seq: 0, recent: [] });

let state: IpLookupState = EMPTY;
const listeners = new Set<() => void>();

function emit(next: IpLookupState) {
  state = next;
  for (const l of Array.from(listeners)) l();
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => {
    listeners.delete(l);
  };
}

function getSnapshot(): IpLookupState {
  return state;
}

// Must be referentially stable across calls or React loops during hydration.
function getServerSnapshot(): IpLookupState {
  return EMPTY;
}

const MAX_RECENT = 8;

function remember(recent: IpQuery[], q: IpQuery): IpQuery[] {
  return [q, ...recent.filter((r) => !(r.address === q.address && r.mode === q.mode))].slice(0, MAX_RECENT);
}

/** Open the drawer. With no address it opens on the empty prompt, which is the
 *  ⌘K entry point; with one it opens and immediately runs that lookup. */
export function openIpLookup(address?: string, mode?: unknown): void {
  const addr = (address ?? "").trim();
  if (!addr) {
    // Already open: nothing changes, so nothing is emitted. Re-opening an open
    // drawer must not churn every subscriber's render.
    if (state.open) return;
    emit({ ...state, open: true });
    return;
  }
  const q: IpQuery = { address: addr, mode: normaliseMode(mode) };
  emit({ open: true, query: q, seq: state.seq + 1, recent: remember(state.recent, q) });
}

/** Issue (or re-issue) a query without touching whether the drawer is open. */
export function setIpLookupQuery(address: string, mode: IpMode = DEFAULT_IP_MODE): void {
  const addr = address.trim();
  if (!addr) return;
  const q: IpQuery = { address: addr, mode };
  emit({ ...state, query: q, seq: state.seq + 1, recent: remember(state.recent, q) });
}

/** Close the drawer, keeping the last query so reopening shows what was asked. */
export function closeIpLookup(): void {
  if (!state.open) return;
  emit({ ...state, open: false });
}

/** Clear the query without closing — back to the empty prompt. */
export function clearIpLookupQuery(): void {
  emit({ ...state, query: null });
}

export interface IpLookupController extends Omit<IpLookupState, "open"> {
  /** `open()` for the empty prompt, `open("10.30.7.7")` to run one. */
  open: (address?: string, mode?: unknown) => void;
  close: () => void;
  /** Run a query in the already-open drawer (the query bar's Enter key). */
  run: (address: string, mode?: IpMode) => void;
  clear: () => void;
  /** Whether the drawer is on screen. `open` is the verb, `isOpen` the state —
   *  the two cannot share a name, and the verb is what call sites want. */
  isOpen: boolean;
}

/**
 * The hook other screens call.
 *
 *   const ip = useIpLookup();
 *   <button onClick={() => ip.open("10.30.7.7")}>10.30.7.7</button>
 *
 * Subscribing is cheap and the state is tiny, so a caller that only ever opens
 * the drawer pays a render when it opens elsewhere. That is the trade for not
 * needing a provider; if it ever matters, `openIpLookup` is a plain function and
 * costs nothing.
 */
export function useIpLookup(): IpLookupController {
  const s = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const open = useCallback((address?: string, mode?: unknown) => openIpLookup(address, mode), []);
  const close = useCallback(() => closeIpLookup(), []);
  const run = useCallback((address: string, mode?: IpMode) => setIpLookupQuery(address, mode), []);
  const clear = useCallback(() => clearIpLookupQuery(), []);
  return { ...s, isOpen: s.open, open, close, run, clear };
}
