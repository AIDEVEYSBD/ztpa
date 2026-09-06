"use client";

/**
 * The admin Configuration screen — where this deployment's AI provider is
 * chosen, and the first screen in the console that WRITES infrastructure.
 *
 * WHY IT EXISTS. Until now the provider was environment-only: `ADVISORY_PROVIDER`,
 * `AZURE_AI_ENDPOINT`, `AZURE_AI_DEPLOYMENT` (backend/src/settings.py). On Azure
 * Container Apps an environment change is a new revision — a deploy — so
 * "point the advisory layer at our own Foundry deployment" was a pipeline change,
 * invisible to the product's own audit trail and attributable to nobody. The row
 * behind this screen (`ztpa.ai_config`, db/migrations/0004_ai_config.sql) makes
 * it an admin action with a name and a timestamp on it.
 *
 * THE DISCIPLINE THIS SCREEN INHERITS, restated because it is easier to break
 * here than anywhere else in the console: IT NEVER SHOWS A CONFIDENT VALUE
 * DERIVED FROM A FAILURE. Three specific ways that could happen here, and what
 * stops each:
 *
 *  1. AN EMPTY DROPDOWN IS AMBIGUOUS, AND AZURE MAKES IT WORSE. Azure Resource
 *     Manager filters list results by role assignment, so an identity with no
 *     Reader receives an empty 200 — not a 403. "No resource groups" and "your
 *     identity cannot see any" would be the SAME WIRE RESPONSE, and a dropdown
 *     that renders `[]` as "none" would be telling an operator their
 *     subscription is empty on the strength of a permissions failure. The
 *     backend refuses to pass that ambiguity on: every discovery route raises a
 *     TYPED error envelope (`{code, detail, azure_detail}`) rather than
 *     returning `[]`, so an empty list arriving here is a positive "Azure was
 *     asked, and answered none". This screen holds up its end — the four
 *     dropdown states below are kept apart by construction, `EMPTY` still says
 *     what an ARM empty does and does not prove, and a failure prints ARM's own
 *     words (`ArmDetail`) rather than a paraphrase.
 *
 *  2. SAVED IS NOT LIVE. The stored row loses to the `AI_CONFIG_IGNORE_DB`
 *     break-glass, is not read at all when the store is unreachable, and does
 *     not exist before the first save. `GET /api/admin/ai/config` therefore
 *     serves the stored row AND what it resolves to, and this screen renders
 *     BOTH with the origin of each block, so "I saved it" and "it is in effect"
 *     are never conflated. A save is confirmed by re-reading, not by the PUT's
 *     status.
 *
 *  3. A FAILED TEST IS NOT A FAILED REQUEST. `POST /api/admin/ai/test` answering
 *     200 with `ok: false` means the backend reached the provider and the
 *     provider refused; a rejection means nobody answered and the test result is
 *     unknown. The first is rendered as a verdict, the second as an ErrorState.
 *
 * MANUAL MODE EXISTS FOR THE OPERATOR WITH NO ARM PERMISSION AT ALL, so it is
 * not gated behind a successful discovery call and issues no ARM request of any
 * kind. That is the whole reason for the escape hatch: an identity that cannot
 * enumerate resource groups can still point the app at an endpoint it knows.
 *
 * AND THERE IS NO API-KEY INPUT ON THIS SCREEN, deliberately. `ztpa.ai_config`
 * has no column that could hold one and must never grow one: the row is read on
 * every model call, lands in every `pg_dump`, and is served by this very
 * endpoint. The key lives in the deployment's environment (`AZURE_AI_API_KEY`,
 * a Container Apps secret) and the screen only ever reports whether one is
 * present — a write-only credential, surfaced as a "configured" indicator. A
 * password box here that silently dropped its contents would be exactly the
 * class of lie the rest of this file is built to prevent.
 */

import {
  cloneElement, isValidElement, useCallback, useEffect, useMemo, useState,
  type ReactElement, type ReactNode,
} from "react";
import { useSession } from "next-auth/react";
import {
  AlertTriangle, Check, Cloud, Cog, FlaskConical, KeyRound, Pencil,
  RotateCw, Save, Search, ShieldCheck,
} from "lucide-react";
import { ApiError, AzureDiscoveryError, api, asApiError } from "@/lib/api";
import type {
  AiActiveConfig, AiConfigOrigin, AiConfigResponse, AiConfigSave, AiConfigSource, AiProvider,
  AiStoredConfig, AiTestResult, AzureAiAccount, AzureAuthMode, AzureDeployment, AzureDiscovery,
  AzureResourceGroup, AzureSubscription,
} from "@/lib/types";
import { isAdmin, type AppRole } from "@/lib/roles";
import { Chip, Skeleton, cn } from "../ui";
import { ErrorState, InlineError, Spinner } from "../ui/Feedback";

// ───────────────────────────────────────────────────────────────────────────
// Vocabulary
// ───────────────────────────────────────────────────────────────────────────

const PROVIDERS: { id: AiProvider; label: string; note: string }[] = [
  { id: "auto", label: "Automatic", note: "Let the backend pick the best provider it can actually reach, in its built-in order. This is the shipped default." },
  { id: "azure", label: "Azure AI Foundry", note: "Call a model deployment on your own Azure AI / Cognitive Services account. Requires an endpoint and a deployment below." },
  { id: "openai", label: "OpenAI", note: "Hosted OpenAI. The key comes from this deployment's OPENAI_API_KEY, never from here." },
  { id: "anthropic", label: "Anthropic", note: "Hosted Anthropic. The key comes from this deployment's ANTHROPIC_API_KEY, never from here." },
  { id: "ollama", label: "Ollama (local)", note: "A local Ollama host. The only setting under which no prompt content leaves this machine." },
];

/** What each `source` value means for the operator standing in front of it.
 *  `tone` drives the colour: two of these five mean the saved row is NOT the
 *  configuration this deployment is running on. */
const SOURCE_NOTE: Record<AiConfigSource, { tone: "ok" | "neutral" | "warn"; text: string }> = {
  database: { tone: "ok", text: "Read from the stored configuration — the choice saved on this screen is the one in effect." },
  defaults: { tone: "neutral", text: "No configuration has been saved on this deployment yet, so its environment variables are deciding. Saving below takes over." },
  stale: {
    tone: "warn",
    text:
      "The configuration store could not be read just now, so the backend is still using the last configuration it successfully read in this process. " +
      "Nothing has moved, but a save made here may not be picked up until the database is reachable again.",
  },
  unavailable: {
    tone: "warn",
    text:
      "The configuration store could not be read and nothing has ever been read from it in this process, so routing has fallen back to this deployment's " +
      "environment. Model calls may be going somewhere other than what was configured here — this is not the same thing as nothing being configured.",
  },
  ignored: {
    tone: "warn",
    text:
      "AI_CONFIG_IGNORE_DB is set on this deployment: the stored row is being ignored on purpose (it is the break-glass for a bad saved configuration). " +
      "Saving here still writes the row, and this deployment will not act on it until that variable is removed and the app restarts.",
  },
};

const ORIGIN_LABEL: Record<AiConfigOrigin, string> = {
  database: "saved here",
  environment: "this deployment's environment",
  default: "built-in default",
};

/**
 * Empty-list copy, per level. Every one of these says what an empty list from
 * ARM does and does not prove, because ARM's list APIs are RBAC-filtered and
 * therefore cannot distinguish "there are none" from "you may not see them".
 * The backend says so when it can (`unavailable_reason`); when it cannot, the
 * ambiguity is the honest answer and it is printed rather than resolved.
 */
const EMPTY: Record<"subscriptions" | "groups" | "accounts" | "deployments", string> = {
  subscriptions:
    "Azure answered, and this identity can see no subscriptions at all — which means it holds no role assignment " +
    "anywhere, not that your tenant has none. Grant it the built-in Reader role on the subscription that owns your " +
    "Azure AI Foundry account, or use Configure manually.",
  groups:
    "Azure Resource Manager answered, and listed no resource groups. ARM filters this list by role assignment, so this reads equally as " +
    "“the subscription has none” and “this identity has Reader on none of them” — the response is identical either way, and nothing here can tell them apart. " +
    "If you already know the endpoint, use Configure manually.",
  accounts:
    "Azure Resource Manager answered, and listed no Azure AI / Cognitive Services accounts in this resource group that this identity can see. " +
    "As above, an ARM list is RBAC-filtered, so absence here is not proof of absence in the subscription.",
  deployments:
    "Azure Resource Manager answered, and listed no model deployments on this account that this identity can see. " +
    "Create one in Azure AI Foundry, or use Configure manually if you know the deployment name.",
};

// ───────────────────────────────────────────────────────────────────────────
// Feed state — the four things a dropdown can be, kept apart on purpose
// ───────────────────────────────────────────────────────────────────────────

/**
 * `idle` is a real state and not a synonym for empty: the accounts list before a
 * resource group has been picked is NOT APPLICABLE, and rendering it as "no
 * accounts" would be a claim about an Azure estate nobody has looked at yet.
 * `unknown` is the 200-with-a-reason case; `error` is the rejection.
 */
type Feed<T> =
  | { state: "idle" }
  | { state: "loading" }
  | { state: "ok"; items: T[]; incomplete?: string }
  | { state: "unknown"; reason: string }
  | { state: "error"; error: ApiError };

const IDLE = { state: "idle" } as const;
const LOADING = { state: "loading" } as const;

/**
 * One discovery read, with the staleness guard the cascade needs: a slow answer
 * for resource group A must never populate the dropdown after the operator has
 * moved to B, because the list would then describe a scope other than the one
 * on screen.
 *
 * `enabled` is how manual mode issues NO ARM CALL AT ALL — not a call whose
 * result is hidden. An operator with no ARM permission must be able to finish
 * this screen without a single discovery request being made on their behalf.
 */
function useDiscovery<T>(run: () => Promise<AzureDiscovery<T>>, enabled: boolean) {
  const [feed, setFeed] = useState<Feed<T>>(enabled ? LOADING : IDLE);
  const [attempt, setAttempt] = useState(0);
  const reload = useCallback(() => setAttempt((n) => n + 1), []);

  useEffect(() => {
    if (!enabled) {
      setFeed(IDLE);
      return;
    }
    let live = true;
    setFeed(LOADING);
    run()
      .then((d) => {
        if (!live) return;
        // Three distinct answers, kept apart. `unavailable_reason` with nothing
        // behind it means the lookup did not happen at all; `incomplete_reason`
        // means it happened and was CUT OFF at the endpoint's bound. Only a
        // clean, complete, empty list is allowed to reach the "none" copy.
        const missing = d.unavailable_reason?.trim();
        if (missing && d.items.length === 0) setFeed({ state: "unknown", reason: missing });
        else setFeed({
          state: "ok",
          items: d.items,
          incomplete: d.incomplete_reason?.trim() || missing || undefined,
        });
      })
      .catch((e) => {
        if (live) setFeed({ state: "error", error: asApiError(e) });
      });
    return () => {
      live = false;
    };
  }, [run, enabled, attempt]);

  return { feed, reload };
}

// ───────────────────────────────────────────────────────────────────────────
// The draft the form edits
// ───────────────────────────────────────────────────────────────────────────

interface Draft {
  provider: AiProvider;
  endpoint: string;
  deployment: string;
  apiVersion: string;
  authMode: AzureAuthMode;
  clientId: string;
}

const BLANK: Draft = {
  provider: "auto",
  endpoint: "",
  deployment: "",
  apiVersion: "",
  authMode: "identity",
  clientId: "",
};

/** The stored row as a draft. Only ever called with a row that was actually
 *  read — a failed read leaves the form on `BLANK` and the screen on an error
 *  panel, never on a form that looks like an unconfigured deployment. */
function draftOf(stored: AiStoredConfig): Draft {
  return {
    provider: (stored.provider ?? "auto") as AiProvider,
    endpoint: stored.azure_endpoint ?? "",
    deployment: stored.azure_deployment ?? "",
    apiVersion: stored.azure_api_version ?? "",
    authMode: (stored.azure_auth_mode ?? "identity") as AzureAuthMode,
    clientId: stored.azure_client_id ?? "",
  };
}

const sameDraft = (a: Draft, b: Draft) =>
  a.provider === b.provider && a.endpoint === b.endpoint && a.deployment === b.deployment &&
  a.apiVersion === b.apiVersion && a.authMode === b.authMode && a.clientId === b.clientId;

/** Empty string -> null, so a cleared field is stored as "unset" rather than as
 *  the empty string, which the backend's CHECK constraints treat differently. */
const orNull = (v: string) => (v.trim() ? v.trim() : null);

/** Local time with seconds — an operator correlating a save with a container log
 *  needs the second, and "3 minutes ago" is unusable for that. */
function when(ts: string | null | undefined): string {
  if (!ts) return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString(undefined, { hour12: false });
}

// ───────────────────────────────────────────────────────────────────────────
// The screen
// ───────────────────────────────────────────────────────────────────────────

export function AiConfigAdmin() {
  // `status` matters as much as the role here. While the session is still being
  // fetched the role is not "none", it is UNKNOWN, and rendering the 403 panel
  // in that window would tell an administrator they are not permitted — the same
  // empty-vs-failed lie, wearing a permissions costume.
  const { data: session, status } = useSession();
  const role = ((session?.user as { role?: AppRole | null } | undefined)?.role ?? null) as AppRole | null;
  const admin = status !== "loading" && isAdmin(role);

  const [cfg, setCfg] = useState<AiConfigResponse>();
  const [cfgErr, setCfgErr] = useState<ApiError>();
  const [loading, setLoading] = useState(true);

  const [draft, setDraft] = useState<Draft>(BLANK);
  const [mode, setMode] = useState<"auto" | "manual">("auto");

  const [sub, setSub] = useState("");
  const [rg, setRg] = useState("");
  const [account, setAccount] = useState("");

  const [saving, setSaving] = useState(false);
  const [saveErr, setSaveErr] = useState<ApiError>();
  const [savedAt, setSavedAt] = useState<string>();

  const [testing, setTesting] = useState(false);
  const [testErr, setTestErr] = useState<ApiError>();
  const [test, setTest] = useState<AiTestResult>();

  // The draft that corresponds to what is currently stored, so "dirty" is a
  // comparison against the server's row rather than against the last keystroke.
  const baseline = useMemo(() => (cfg ? draftOf(cfg.stored) : BLANK), [cfg]);
  const dirty = !sameDraft(draft, baseline);

  const load = useCallback(() => {
    setLoading(true);
    setCfgErr(undefined);
    return api.aiConfig()
      .then((r) => {
        setCfg(r);
        setDraft(draftOf(r.stored));
        return true;
      })
      // Never `setCfg(<empty>)`: an unreadable configuration store rendered as an
      // unconfigured deployment would invite an operator to "fix" a configuration
      // that already exists, and the backend distinguishes the two on purpose
      // (ai_config.load raises rather than returning defaults). The boolean is
      // what lets a SAVE report "accepted but not read back" rather than "saved".
      .catch((e) => {
        setCfg(undefined);
        setCfgErr(asApiError(e));
        return false;
      })
      .finally(() => setLoading(false));
  }, []);

  // Admin-gated at the source, so the "nothing is fetched" promise the role gate
  // below makes is literally true rather than a description of what the screen
  // renders after the request has already gone out.
  useEffect(() => { if (admin) load(); }, [admin, load]);

  // Discovery. `enabled` is false in manual mode and for a non-azure provider,
  // so neither issues an ARM request — see the note on `useDiscovery`.
  const discovering = mode === "auto" && draft.provider === "azure" && admin;
  const loadSubs = useCallback(() => api.azureSubscriptions(), []);
  const loadGroups = useCallback(() => api.azureResourceGroups(sub || undefined), [sub]);
  const loadAccounts = useCallback(() => api.azureAccounts(rg, sub || undefined), [rg, sub]);
  const loadDeployments = useCallback(() => api.azureDeployments(rg, account, sub || undefined), [rg, account, sub]);

  const subs = useDiscovery<AzureSubscription>(loadSubs, discovering);

  // With exactly one subscription visible, it is not a guess — it is the answer,
  // and it is the one the backend would default to anyway. With several, the
  // backend REFUSES to pick (quietly enumerating the wrong estate would report
  // the operator's own Foundry account as missing), so the dropdown is how the
  // question gets asked instead of arriving as an error.
  const onlySub = subs.feed.state === "ok" && subs.feed.items.length === 1 ? subs.feed.items[0].id : "";
  useEffect(() => { if (onlySub && !sub) setSub(onlySub); }, [onlySub, sub]);

  // Everything below the subscription waits for one to be chosen — unless the
  // subscription list itself could not be read, in which case the lower calls are
  // still worth making: a deployment that pins AZURE_SUBSCRIPTION_ID resolves the
  // scope server-side and needs no dropdown at all.
  const scoped = subs.feed.state === "ok" ? !!sub : (subs.feed.state === "error" || subs.feed.state === "unknown");

  const groups = useDiscovery<AzureResourceGroup>(loadGroups, discovering && scoped);
  const accounts = useDiscovery<AzureAiAccount>(loadAccounts, discovering && scoped && !!rg);
  const deployments = useDiscovery<AzureDeployment>(loadDeployments, discovering && scoped && !!rg && !!account);

  // Reflect the saved target back into the cascade when the operator lands on
  // the resource group that contains it, so the dropdowns show the current
  // configuration instead of looking unset. Only ever fills a blank selection.
  const savedEndpoint = cfg?.stored.azure_endpoint ?? "";
  const savedDeployment = cfg?.stored.azure_deployment ?? "";
  useEffect(() => {
    if (account || accounts.feed.state !== "ok" || !savedEndpoint) return;
    const hit = accounts.feed.items.find((a) => sameEndpoint(a.endpoint, savedEndpoint));
    if (hit) setAccount(hit.name);
  }, [account, accounts.feed, savedEndpoint]);

  const selectedAccount =
    accounts.feed.state === "ok" ? accounts.feed.items.find((a) => a.name === account) : undefined;

  // Picking an account IS picking an endpoint: ARM reports the account's
  // data-plane host and that is exactly what gets stored, so there is nothing
  // for the operator to type or mistype.
  const accountEndpoint = selectedAccount?.endpoint ?? "";
  useEffect(() => {
    if (!accountEndpoint) return;
    setDraft((d) => (d.endpoint === accountEndpoint ? d : { ...d, endpoint: accountEndpoint }));
  }, [accountEndpoint]);

  // The same reflection for the deployment, with the same guard: a name is only
  // selected when ARM actually listed it on this account. Selecting one that is
  // not in the fetched list would be a value invented by the UI out of a row
  // that may describe a different account entirely.
  const savedDeploymentListed =
    deployments.feed.state === "ok" && deployments.feed.items.some((d) => d.name === savedDeployment);
  useEffect(() => {
    if (!savedDeployment || !savedDeploymentListed) return;
    setDraft((d) => (d.deployment ? d : { ...d, deployment: savedDeployment }));
  }, [savedDeployment, savedDeploymentListed]);

  const save = async () => {
    setSaving(true);
    setSaveErr(undefined);
    setSavedAt(undefined);
    const body: AiConfigSave = {
      provider: draft.provider,
      azure_endpoint: orNull(draft.endpoint),
      azure_deployment: orNull(draft.deployment),
      azure_api_version: orNull(draft.apiVersion),
      azure_auth_mode: draft.authMode,
      azure_client_id: orNull(draft.clientId),
    };
    try {
      await api.saveAiConfig(body);
      // A 200 on the PUT means the row was accepted, NOT that this deployment is
      // now routing on it — the break-glass variable and an unreadable store both
      // beat a stored row. Re-read, and let the active panel below say which.
      await load();
      setSavedAt(new Date().toISOString());
      // The verdict below described the PREVIOUS configuration. Leaving "The
      // model answered" on screen under a target that has just changed would be
      // a result attributed to a call that was never made against it.
      setTest(undefined);
      setTestErr(undefined);
    } catch (e) {
      setSaveErr(asApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTestErr(undefined);
    setTest(undefined);
    try {
      const r = await api.testAiConfig();
      // Contract check. A body without a boolean `ok` is a build mismatch, and
      // rendering it as a verdict would be a claim about a model call whose
      // outcome we do not actually have.
      if (typeof r?.ok !== "boolean") {
        setTestErr(new ApiError(
          200,
          "The API answered, but not with the test-result shape this screen reads ({ok, provider, ...}). " +
            "The frontend and backend are probably different builds, so whether the model call succeeded is unknown.",
          "/api/admin/ai/test",
        ));
        return;
      }
      setTest(r);
    } catch (e) {
      setTestErr(asApiError(e));
    } finally {
      setTesting(false);
    }
  };

  // The role is not known yet. Neither the screen nor the 403 may be asserted
  // from here, so the skeleton stands in for both.
  if (status === "loading") return <ConfigSkeleton />;

  // Role gate. The API is the real one — this screen cannot grant itself
  // anything — but the nav entry is admin-only and so is this, so a non-admin
  // arriving by any other route gets the permissions decision phrased as one
  // rather than as an outage. Nothing is fetched, and no ARM call is made.
  if (!isAdmin(role)) {
    return (
      <ErrorState
        resource="the AI configuration"
        error={new ApiError(
          403,
          "Configuring the AI provider is restricted to administrators — it decides where this product sends " +
            "network topology, firewall rules and asset names. Your session carries the role " + (role ?? "none") + ".",
          "/api/admin/ai/config",
        )}
      />
    );
  }

  if (cfgErr) {
    return (
      <div className="space-y-3">
        {/* A save that was accepted and then could not be read back. Neither
            "saved" nor "failed" is true here, and picking either would be the
            screen inventing an outcome it does not have. */}
        {savedAt && (
          <p role="alert" className="border border-sev-medium-line bg-sev-medium-bg p-3 text-[12px] leading-relaxed text-text2">
            Your change was accepted by the API at <span className="mono">{when(savedAt)}</span> — and could not be read
            back. What is now stored, and what this deployment is routing on, is therefore unknown: the write may have
            landed exactly as sent, or the store may have become unreachable between the write and the read. Retry
            below before assuming either.
          </p>
        )}
        <ErrorState resource="the AI configuration" error={cfgErr} onRetry={load} />
      </div>
    );
  }

  if (loading && !cfg) return <ConfigSkeleton />;

  // `cfg` is defined here: the error branch returned and the loading branch
  // covers the only other way it can be undefined.
  const stored = cfg!.stored;
  const active = cfg!.active ?? undefined;
  const azure = draft.provider === "azure";
  const providerNote = PROVIDERS.find((p) => p.id === draft.provider)?.note ?? "";
  // The one field-level check worth doing in the browser, because the backend
  // refuses it too (the ai_config_azure_target_complete constraint) and a
  // round-trip to be told so is a worse experience than a disabled button with
  // a reason next to it.
  const incomplete = azure && !(draft.endpoint.trim() && draft.deployment.trim());

  return (
    <div className="space-y-5">
      <p className="max-w-3xl text-[13px] text-text2">
        Which model this deployment sends prompts to, saved in the database with your name and the time on it
        (<span className="mono">ztpa.ai_config</span>) rather than baked into a container revision. Changing it takes
        effect on the next model call — no redeploy. API keys are never stored here: they come from this
        deployment&apos;s environment.
      </p>

      <ActivePanel stored={stored} active={active} onRetry={load} />

      <div className="panel">
        <div className="panel-head">
          <span className="label flex items-center gap-1.5"><Cog size={13} /> Provider</span>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setMode(mode === "auto" ? "manual" : "auto")}
              className="btn-ghost !h-7 text-[11px]"
              aria-pressed={mode === "manual"}
            >
              {mode === "auto" ? <><Pencil size={12} /> Configure manually</> : <><Search size={12} /> Back to discovery</>}
            </button>
          </div>
        </div>

        <div className="space-y-4 p-4">
          <Field label="Provider" htmlFor="ai-provider" hint={providerNote}>
            <select
              id="ai-provider"
              className="field w-full max-w-md"
              value={draft.provider}
              onChange={(e) => setDraft({ ...draft, provider: e.target.value as AiProvider })}
            >
              {PROVIDERS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
          </Field>

          {azure && mode === "auto" && (
            <AutomaticAzure
              sub={sub}
              setSub={(v) => {
                // A subscription change invalidates everything under it: the
                // resource group, the account and the endpoint it supplied all
                // describe a different estate.
                setSub(v); setRg(""); setAccount("");
                setDraft((d) => ({ ...d, endpoint: "", deployment: "" }));
              }}
              rg={rg}
              setRg={(v) => { setRg(v); setAccount(""); setDraft((d) => ({ ...d, endpoint: "", deployment: "" })); }}
              account={account}
              setAccount={(v) => { setAccount(v); setDraft((d) => ({ ...d, deployment: "" })); }}
              deployment={draft.deployment}
              setDeployment={(v) => setDraft((d) => ({ ...d, deployment: v }))}
              subs={subs}
              groups={groups}
              accounts={accounts}
              deployments={deployments}
              endpoint={draft.endpoint}
              onManual={() => setMode("manual")}
            />
          )}

          {azure && mode === "manual" && (
            <ManualAzure draft={draft} setDraft={setDraft} defaultApiVersion={cfg!.default_api_version} />
          )}

          {azure && (
            <AzureAuth draft={draft} setDraft={setDraft} keyPresent={active?.key_present} />
          )}

          {!azure && draft.provider !== "auto" && (
            <p className="border border-hair bg-sunk p-3 text-[12px] leading-relaxed text-text2">
              Nothing else to configure here for this provider: its credential and host come from this deployment&apos;s
              environment, which is the only place this product reads a secret from.
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2 border-t border-hair pt-4">
            <button type="button" onClick={save} disabled={saving || !dirty || incomplete} className="btn-primary">
              {saving ? <Spinner label="Saving…" /> : <><Save size={13} /> Save configuration</>}
            </button>
            {dirty && !incomplete && !saving && (
              <span className="text-[11.5px] text-text3">Unsaved changes.</span>
            )}
            {!dirty && !saving && (
              <span className="text-[11.5px] text-text3">This form matches the stored configuration.</span>
            )}
            {incomplete && (
              <span className="text-[11.5px] text-sev-high">
                Provider &ldquo;Azure AI Foundry&rdquo; needs both an endpoint and a deployment. A half-configured
                Azure provider routes every model call at nothing and degrades to the deterministic fallback, which
                reads to a user as a weak model rather than as an unfinished form.
              </span>
            )}
            {savedAt && !dirty && !saveErr && (
              <span className="flex items-center gap-1.5 text-[11.5px] text-ok">
                <Check size={12} /> Saved and read back at {when(savedAt)}.
              </span>
            )}
          </div>
          {saveErr && (
            <InlineError resource="the configuration save" error={saveErr} onRetry={save} />
          )}
        </div>
      </div>

      <TestPanel
        running={testing}
        result={test}
        error={testErr}
        dirty={dirty}
        onRun={runTest}
      />
    </div>
  );
}

/** The shape of the screen before anything about it is known — the session's
 *  role included. Deliberately shows no field values and no counts. */
function ConfigSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-4 w-3/4 max-w-2xl" />
      <div className="panel space-y-3 p-4">
        <Skeleton className="h-3.5 w-40" />
        <Skeleton className="h-3.5 w-72" />
        <Skeleton className="h-3.5 w-56" />
      </div>
      <div className="panel space-y-3 p-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="space-y-1.5"><Skeleton className="h-3 w-28" /><Skeleton className="h-8 w-full max-w-md" /></div>
        ))}
      </div>
    </div>
  );
}

/** Two endpoints are the same target if they differ only by case or a trailing
 *  slash — the shapes ARM and an operator's clipboard produce respectively. */
function sameEndpoint(a: string, b: string): boolean {
  const norm = (v: string) => v.trim().replace(/\/+$/, "").toLowerCase();
  return !!a && norm(a) === norm(b);
}

// ───────────────────────────────────────────────────────────────────────────
// What is actually in effect
// ───────────────────────────────────────────────────────────────────────────

function ActivePanel({ stored, active, onRetry }: {
  stored: AiStoredConfig;
  active?: AiActiveConfig;
  onRetry: () => void;
}) {
  const source = active?.config_source ?? stored.source;
  const note = SOURCE_NOTE[source] ?? { tone: "neutral" as const, text: `The backend reported the configuration source as "${source}".` };
  // The comparison that matters: a row exists, and it is not the one being used.
  const overridden = stored.is_stored && !!active && active.provider_origin !== "database";

  return (
    <div className="panel">
      <div className="panel-head">
        <span className="label flex items-center gap-1.5"><ShieldCheck size={13} /> Currently active</span>
        <button type="button" onClick={onRetry} className="btn-ghost !h-7 text-[11px]"><RotateCw size={12} /> Re-read</button>
      </div>
      <div className="space-y-3 p-4">
        {active ? (
          <>
            <dl className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
              <Row label="Provider" value={active.provider} origin={active.provider_origin} />
              {active.provider === "azure" && (
                <>
                  <Row label="Endpoint" value={active.azure_endpoint} origin={active.azure_origin} mono />
                  <Row label="Deployment" value={active.azure_deployment} origin={active.azure_origin} mono />
                  <Row label="API version" value={active.azure_api_version} origin={active.azure_origin} mono />
                  <Row label="Authentication" value={active.azure_auth_mode === "key" ? "API key (from the environment)" : "Managed identity"} origin={active.azure_origin} />
                  {active.azure_client_id && <Row label="Identity client id" value={active.azure_client_id} origin={active.azure_origin} mono />}
                </>
              )}
            </dl>

            {active.azure_endpoint_error && (
              <p role="alert" className="border border-sev-critical-line bg-sev-critical-bg p-2.5 text-[12px] leading-relaxed text-sev-critical">
                The configured endpoint is not usable as one, so the Azure provider is unavailable and model-backed
                capabilities are falling back to their deterministic output: {active.azure_endpoint_error}
              </p>
            )}

            {typeof active.ready === "boolean" && (
              <div className="flex flex-wrap items-start gap-2 text-[12px]">
                <Chip variant={active.ready ? "ok" : "warn"} dot>
                  {active.ready ? "Can make a call" : "Cannot make a call"}
                </Chip>
                {!active.ready && active.reason && <span className="text-text2">{active.reason}</span>}
              </div>
            )}
          </>
        ) : (
          // The API answered without the resolution block. Saying so beats
          // showing the stored row under a heading that claims it is live.
          <p role="status" className="border border-sev-medium-line bg-sev-medium-bg p-2.5 text-[12px] leading-relaxed text-text2">
            This API build did not report which configuration it is actually routing on, only what is stored. What is
            saved below may or may not be what this deployment is using — the two differ whenever the store is
            unreadable or the AI_CONFIG_IGNORE_DB break-glass is set, and neither can be ruled out from here.
          </p>
        )}

        <p className={cn(
          "border p-2.5 text-[12px] leading-relaxed",
          note.tone === "ok" ? "border-ok-line bg-ok-bg text-text2"
            : note.tone === "warn" ? "border-sev-medium-line bg-sev-medium-bg text-text2"
            : "border-hair bg-sunk text-text2",
        )}>
          {note.text}
        </p>

        {overridden && (
          <p role="alert" className="border border-sev-high-line bg-sev-high-bg p-2.5 text-[12px] leading-relaxed text-sev-high">
            A configuration is saved on this deployment and it is <strong>not</strong> the one in effect — the backend
            is routing on {ORIGIN_LABEL[active!.provider_origin]}. Until that is resolved, changes saved here will not
            change where prompts go.
          </p>
        )}

        <p className="text-[11.5px] text-text3">
          {stored.is_stored
            ? <>Saved by <span className="text-text2">{stored.configured_by || "an unattributed actor"}</span>{stored.updated_at ? <> at <span className="mono">{when(stored.updated_at)}</span></> : null}.</>
            : "Nothing has been saved on this screen yet."}
        </p>
      </div>
    </div>
  );
}

function Row({ label, value, origin, mono = false }: {
  label: string; value: string; origin: AiConfigOrigin; mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="label text-[10px]">{label}</dt>
      <dd className="mt-0.5 flex flex-wrap items-baseline gap-2">
        {/* An empty resolved field is "not set", never a blank that reads as a
            value the reader has to guess at. */}
        <span className={cn("min-w-0 break-all text-[13px] font-bold", mono && "mono", !value && "font-normal text-text3")}>
          {value || "not set"}
        </span>
        <span className="text-[11px] text-text3">from {ORIGIN_LABEL[origin]}</span>
      </dd>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Automatic mode — the cascading dropdowns
// ───────────────────────────────────────────────────────────────────────────

type Discovered<T> = { feed: Feed<T>; reload: () => void };

function AutomaticAzure({
  sub, setSub, rg, setRg, account, setAccount, deployment, setDeployment,
  subs, groups, accounts, deployments, endpoint, onManual,
}: {
  sub: string; setSub: (v: string) => void;
  rg: string; setRg: (v: string) => void;
  account: string; setAccount: (v: string) => void;
  deployment: string; setDeployment: (v: string) => void;
  subs: Discovered<AzureSubscription>;
  groups: Discovered<AzureResourceGroup>;
  accounts: Discovered<AzureAiAccount>;
  deployments: Discovered<AzureDeployment>;
  endpoint: string;
  onManual: () => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-[12px] leading-relaxed text-text3">
        Read live from Azure Resource Manager with this deployment&apos;s identity — in the container, the managed
        identity attached to the app; on a developer machine, your <span className="mono">az login</span>. The identity
        that fills these lists is the identity that will make the model calls, so a dropdown that fills is evidence
        about the thing being configured. Nothing is typed, so nothing is mistyped.
      </p>

      <DiscoverySelect
        id="az-sub"
        label="Subscription"
        resource="the Azure subscriptions"
        value={sub}
        onChange={setSub}
        feed={subs.feed}
        reload={subs.reload}
        emptyText={EMPTY.subscriptions}
        placeholder="Select a subscription…"
        option={(x: AzureSubscription) => ({
          value: x.id,
          label: `${x.name}${x.state && x.state !== "Enabled" ? ` · ${x.state}` : ""} · ${x.id}`,
        })}
        hint="Only asked when this identity can see more than one: with several visible there is no defensible default, and quietly enumerating the wrong one would report your own Foundry account as missing."
        onManual={onManual}
      />

      <DiscoverySelect
        id="az-rg"
        label="Resource group"
        resource="the Azure resource groups"
        value={rg}
        onChange={setRg}
        feed={groups.feed}
        reload={groups.reload}
        emptyText={EMPTY.groups}
        idleText="Pick a subscription first — nothing has been looked up yet."
        placeholder="Select a resource group…"
        option={(g: AzureResourceGroup) => ({ value: g.name, label: `${g.name} · ${g.location}` })}
        onManual={onManual}
      />

      <DiscoverySelect
        id="az-account"
        label="Azure AI / Foundry account"
        resource="the Azure AI accounts"
        value={account}
        onChange={setAccount}
        feed={accounts.feed}
        reload={accounts.reload}
        emptyText={EMPTY.accounts}
        idleText="Pick a resource group first — nothing has been looked up yet."
        placeholder="Select an account…"
        option={(a: AzureAiAccount) => ({ value: a.name, label: `${a.name} · ${a.kind} · ${a.location}` })}
        onManual={onManual}
      />

      {endpoint && (
        <p className="mono break-all text-[11.5px] text-text3">
          endpoint {endpoint}
        </p>
      )}

      <DiscoverySelect
        id="az-deployment"
        label="Model deployment"
        resource="the model deployments"
        value={deployment}
        onChange={setDeployment}
        feed={deployments.feed}
        reload={deployments.reload}
        emptyText={EMPTY.deployments}
        idleText="Pick an account first — nothing has been looked up yet."
        placeholder="Select a deployment…"
        option={(d: AzureDeployment) => ({
          value: d.name,
          label: [
            d.name,
            d.model && `model ${d.model}`,
            d.version && `v${d.version}`,
            d.sku,
            // Shown, not filtered on. A deployment that cannot serve a chat
            // completion is a 404 waiting to happen, and an operator who cannot
            // see it at all learns nothing about why their deployment is missing.
            d.chat === false && "not a chat deployment",
            d.provisioning_state && d.provisioning_state !== "Succeeded" && d.provisioning_state,
          ].filter(Boolean).join(" · "),
        })}
        hint="This is the DEPLOYMENT name on the account, not the model name. They differ often enough that using one for the other is a 404 at request time."
        onManual={onManual}
      />
    </div>
  );
}

/**
 * One dropdown, plus the state it is in.
 *
 * The select is disabled unless the list was actually read, and every non-`ok`
 * state prints WHY — because a greyed-out empty select with no explanation is
 * the same failure this screen exists to avoid, just quieter. The "Configure
 * manually" affordance is repeated on the failure paths on purpose: the operator
 * whose identity cannot enumerate is exactly the operator the escape hatch is
 * for, and they should not have to scroll back up to find it.
 */
function DiscoverySelect<T>({
  id, label, resource, value, onChange, feed, reload, emptyText, idleText, placeholder, option, hint, onManual,
}: {
  id: string;
  label: string;
  resource: string;
  value: string;
  onChange: (v: string) => void;
  feed: Feed<T>;
  reload: () => void;
  emptyText: string;
  idleText?: string;
  placeholder: string;
  option: (item: T) => { value: string; label: string };
  hint?: string;
  onManual: () => void;
}) {
  const items = feed.state === "ok" ? feed.items : [];
  const usable = feed.state === "ok" && items.length > 0;
  const statusId = `${id}-status`;

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="label block">{label}</label>
      <div className="flex flex-wrap items-center gap-2">
        <select
          id={id}
          className="field w-full max-w-md"
          value={value}
          disabled={!usable}
          aria-busy={feed.state === "loading"}
          aria-describedby={statusId}
          onChange={(e) => onChange(e.target.value)}
        >
          <option value="">{usable ? placeholder : "—"}</option>
          {/* A selection the fetched list does not contain — a saved deployment
              that belongs to a different account, say. Shown and labelled rather
              than silently dropped, which would leave the control blank next to
              a configuration that plainly has a value in it. */}
          {value && !items.some((it) => option(it).value === value) && (
            <option value={value}>{value} — not in this list</option>
          )}
          {items.map((it) => {
            const o = option(it);
            return <option key={o.value} value={o.value}>{o.label}</option>;
          })}
        </select>
        {feed.state !== "idle" && (
          <button type="button" onClick={reload} className="btn-ghost !h-8 text-[11px]" disabled={feed.state === "loading"}>
            <RotateCw size={12} /> {feed.state === "loading" ? "Loading…" : "Reload"}
          </button>
        )}
      </div>

      <div id={statusId} className="space-y-1.5">
        {hint && <p className="text-[11.5px] leading-relaxed text-text3">{hint}</p>}

        {feed.state === "idle" && idleText && (
          <p className="text-[11.5px] text-text3">{idleText}</p>
        )}

        {feed.state === "loading" && (
          <p className="text-[11.5px] text-text3"><Spinner label={`Reading ${resource} from Azure…`} /></p>
        )}

        {/* A rejection. The status and detail carry whether this was a 403 on the
            ARM call, a backend that could not build a credential, or nothing
            answering at all — three different fixes, and the panel names them. */}
        {feed.state === "error" && (
          <>
            <InlineError resource={resource} error={feed.error} onRetry={reload} />
            <ArmDetail error={feed.error} />
            <ManualEscape onManual={onManual} />
          </>
        )}

        {/* The 200 that is not an answer: the backend enumerated nothing and
            said why. Amber, not red — nothing is broken; nothing is KNOWN. */}
        {feed.state === "unknown" && (
          <div role="status" className="border border-sev-medium-line bg-sev-medium-bg p-2.5 text-[12px] leading-relaxed text-text2">
            <div className="font-bold text-sev-medium">{cap(resource)} could not be listed — this list is unknown, not empty.</div>
            <p className="mono mt-1 break-words text-[11px] text-text3">{feed.reason}</p>
            <ManualEscape onManual={onManual} className="mt-1.5" />
          </div>
        )}

        {/* The list is REAL but CUT OFF at the endpoint's bound. A silently
            truncated dropdown fails exactly like an empty one — the operator's
            resource group is simply missing — so the bound is stated. */}
        {feed.state === "ok" && feed.incomplete && (
          <div role="status" className="border border-sev-medium-line bg-sev-medium-bg p-2.5 text-[12px] leading-relaxed text-text2">
            <div className="font-bold text-sev-medium">This list is incomplete — do not read it as everything you have.</div>
            <p className="mt-1 break-words text-[11.5px] text-text3">{feed.incomplete}</p>
            <ManualEscape onManual={onManual} className="mt-1.5" />
          </div>
        )}

        {/* The ONLY place an empty list is allowed to be reported as emptiness —
            and even here it says what an empty ARM list does and does not prove. */}
        {feed.state === "ok" && items.length === 0 && !feed.incomplete && (
          <div role="status" className="border border-hair bg-sunk p-2.5 text-[12px] leading-relaxed text-text2">
            {emptyText}
            <ManualEscape onManual={onManual} className="mt-1.5" />
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The two facts an ARM failure carries that a generic error panel drops.
 *
 * `code` is the backend's machine-readable `ArmError.kind`, so the page can say
 * something specific (the ambiguous-subscription case has an answer sitting in a
 * dropdown three lines up) without parsing an English sentence. `azure_detail`
 * is ARM's own message, which for an authorization failure names the exact
 * missing permission and scope — the single most useful string an operator can
 * be handed, and one no paraphrase improves on.
 */
function ArmDetail({ error }: { error: ApiError }) {
  if (!(error instanceof AzureDiscoveryError)) return null;
  if (!error.code && !error.azureDetail) return null;
  return (
    <div className="space-y-1 border-l-2 border-hair pl-2.5">
      {error.code === "azure_subscription_ambiguous" && (
        <p className="text-[11.5px] leading-relaxed text-text2">
          Choose one in the Subscription dropdown above — this identity can see several, and the backend refuses to
          pick for you rather than enumerate the wrong estate and report your own account as missing.
        </p>
      )}
      {error.code === "azure_credential_unavailable" && (
        <p className="text-[11.5px] leading-relaxed text-text2">
          No Azure credential could be obtained at all, so nothing was asked. Discovery cannot work here — the manual
          configuration can, and needs no ARM permission.
        </p>
      )}
      <div className="mono space-y-0.5 break-words text-[11px] text-text3">
        {error.code && <div>code {error.code}</div>}
        {error.azureDetail && <div>azure said: {error.azureDetail}</div>}
      </div>
    </div>
  );
}

function ManualEscape({ onManual, className }: { onManual: () => void; className?: string }) {
  return (
    <button type="button" onClick={onManual} className={cn("text-[11.5px] font-bold underline", className)}>
      Configure manually instead
    </button>
  );
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

// ───────────────────────────────────────────────────────────────────────────
// Manual mode — no ARM call, ever
// ───────────────────────────────────────────────────────────────────────────

function ManualAzure({ draft, setDraft, defaultApiVersion }: {
  draft: Draft;
  setDraft: (d: Draft) => void;
  /** What the backend would use for an unset version. Read off the config
   *  payload rather than hardcoded here, so the placeholder cannot drift from
   *  the value that would actually be sent. */
  defaultApiVersion?: string;
}) {
  return (
    <div className="space-y-4">
      <p className="border border-hair bg-sunk p-3 text-[12px] leading-relaxed text-text2">
        Manual mode makes <strong>no Azure Resource Manager call at all</strong>. It is here for the identity that
        cannot enumerate resource groups — a locked-down subscription, a sovereign or air-gapped cloud, a gateway in
        front of the model — and it works with no ARM permission of any kind. Type what you already know.
      </p>

      <Field
        label="Endpoint"
        htmlFor="man-endpoint"
        hint="The account's data-plane host, e.g. https://<account>.cognitiveservices.azure.com/. Must be https for a remote host: this product sends firewall rules, asset names and reachability paths to the model. A URL carrying an api-key query string is refused rather than silently stripped."
      >
        <input
          id="man-endpoint"
          type="url"
          inputMode="url"
          spellCheck={false}
          className="field w-full max-w-xl"
          placeholder="https://my-account.cognitiveservices.azure.com/"
          value={draft.endpoint}
          onChange={(e) => setDraft({ ...draft, endpoint: e.target.value })}
        />
      </Field>

      <Field
        label="Deployment name"
        htmlFor="man-deployment"
        hint="The deployment on that endpoint, not the model behind it — e.g. Mistral-Large-3."
      >
        <input
          id="man-deployment"
          spellCheck={false}
          className="field w-full max-w-md"
          placeholder="Mistral-Large-3"
          value={draft.deployment}
          onChange={(e) => setDraft({ ...draft, deployment: e.target.value })}
        />
      </Field>

      <Field
        label="API version"
        htmlFor="man-apiversion"
        hint={
          "Optional. Leave empty to use the application default" +
          (defaultApiVersion ? ` (this build: ${defaultApiVersion})` : "") +
          ", so it can move without a migration; set it to pin a deployment that needs a specific one."
        }
      >
        <input
          id="man-apiversion"
          spellCheck={false}
          className="field w-full max-w-xs"
          placeholder={defaultApiVersion || "2024-10-21"}
          value={draft.apiVersion}
          onChange={(e) => setDraft({ ...draft, apiVersion: e.target.value })}
        />
      </Field>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// Authentication — and the credential this screen deliberately cannot take
// ───────────────────────────────────────────────────────────────────────────

function AzureAuth({ draft, setDraft, keyPresent }: {
  draft: Draft; setDraft: (d: Draft) => void; keyPresent?: boolean;
}) {
  return (
    <div className="space-y-4 border-t border-hair pt-4">
      <Field
        label="Authentication"
        htmlFor="az-auth"
        hint="Managed identity is the intended posture and needs no secret anywhere. Choose API key only for an endpoint with no identity story."
      >
        <select
          id="az-auth"
          className="field w-full max-w-md"
          value={draft.authMode}
          onChange={(e) => setDraft({ ...draft, authMode: e.target.value as AzureAuthMode })}
        >
          <option value="identity">Managed identity (no secret)</option>
          <option value="key">API key from the environment</option>
        </select>
      </Field>

      {draft.authMode === "identity" && (
        <Field
          label="User-assigned identity client id"
          htmlFor="az-clientid"
          hint="Optional GUID. Leave it empty and the credential picks itself — the attached identity in the container, your az login on a developer machine. Set it only when more than one identity is attached and the ambiguity has to be resolved explicitly."
        >
          <input
            id="az-clientid"
            spellCheck={false}
            className="field w-full max-w-md"
            placeholder="00000000-0000-0000-0000-000000000000"
            value={draft.clientId}
            onChange={(e) => setDraft({ ...draft, clientId: e.target.value })}
          />
        </Field>
      )}

      {draft.authMode === "key" && (
        <div className="border border-hair bg-sunk p-3 text-[12px] leading-relaxed text-text2">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <span className="label flex items-center gap-1.5"><KeyRound size={12} /> API key</span>
            {/* Write-only credential, reported as a state and never as a value.
                `undefined` is its own answer: this API build did not say. */}
            {keyPresent === true && <Chip variant="ok" dot>configured in this deployment</Chip>}
            {keyPresent === false && <Chip variant="warn" dot>not set in this deployment</Chip>}
            {keyPresent === undefined && <Chip variant="neutral" dot>the API did not report whether one is set</Chip>}
          </div>
          <p>
            There is no key box on this screen, and that is deliberate: <span className="mono">ztpa.ai_config</span> has
            no column that could hold a secret and must never grow one — the row is read on every model call, lands in
            every <span className="mono">pg_dump</span>, and is served by this admin endpoint. The key lives in the
            deployment&apos;s environment as <span className="mono">AZURE_AI_API_KEY</span>, alongside{" "}
            <span className="mono">OPENAI_API_KEY</span>. Set it once, on the container app:
          </p>
          <pre className="mono mt-2 overflow-x-auto whitespace-pre border border-hair bg-surface2 p-2 text-[11px] text-text2">
{`az containerapp secret set -n npr-backend -g npr-demo-rg \\
  --secrets azure-ai-key=<the key>
az containerapp update -n npr-backend -g npr-demo-rg \\
  --set-env-vars AZURE_AI_API_KEY=secretref:azure-ai-key`}
          </pre>
          <p className="mt-2">
            Saving this form with &ldquo;API key&rdquo; selected while no key is set stores a configuration that cannot
            make a call; the panel above will say so rather than letting it read as a weak model.
          </p>
        </div>
      )}
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────
// The live test
// ───────────────────────────────────────────────────────────────────────────

function TestPanel({ running, result, error, dirty, onRun }: {
  running: boolean;
  result?: AiTestResult;
  error?: ApiError;
  dirty: boolean;
  onRun: () => void;
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <span className="label flex items-center gap-1.5"><FlaskConical size={13} /> Live test</span>
      </div>
      <div className="space-y-3 p-4">
        <p className="text-[12px] leading-relaxed text-text2">
          Sends one real prompt through the configuration this deployment is <strong>currently</strong> using and shows
          exactly what came back — the provider, the deployment, the round-trip time, and a fragment of the model&apos;s
          own words. Not a reachability ping: a 200 from the host with a 401 from the model is a failure, and it is
          reported as one.
        </p>

        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={onRun} disabled={running} className="btn-ghost">
            {running ? <Spinner label="Calling the model…" /> : <><Cloud size={13} /> Run a live test</>}
          </button>
          {dirty && (
            <span className="text-[11.5px] text-sev-medium">
              This tests the <strong>saved</strong> configuration, not the unsaved changes above. Save first to test them.
            </span>
          )}
        </div>

        {/* The request itself failed, so there is no verdict to render. */}
        {error && <InlineError resource="the model test" error={error} onRetry={onRun} />}

        {result && (() => {
          // A latency of zero (or `tested: "nothing"`) means the backend refused
          // to run the probe rather than running one that failed — an unset key,
          // a half-configured target, a posted draft that differs from what is
          // in force. "The call failed" would be a claim about a call nobody made.
          const attempted = (result.latency_ms ?? 0) > 0 && result.tested !== "nothing";
          return (
          <div
            role="status"
            className={cn(
              "border p-3 text-[12px] leading-relaxed",
              result.ok ? "border-ok-line bg-ok-bg" : "border-sev-critical-line bg-sev-critical-bg",
            )}
          >
            <div className={cn("flex flex-wrap items-center gap-2 font-bold", result.ok ? "text-ok" : "text-sev-critical")}>
              {result.ok ? <Check size={14} /> : <AlertTriangle size={14} />}
              {result.ok
                ? "The model answered."
                : attempted
                  ? "The call was made, and it failed."
                  : "No call was made — this configuration cannot make one."}
            </div>
            <dl className="mono mt-2 grid gap-x-6 gap-y-1 text-[11.5px] text-text2 sm:grid-cols-2">
              <Kv k="provider" v={result.provider} />
              <Kv k="model" v={result.model} />
              <Kv k="endpoint" v={result.endpoint} />
              <Kv k="deployment" v={result.deployment} />
              <Kv k="latency" v={typeof result.latency_ms === "number" ? `${Math.round(result.latency_ms)} ms` : null} />
              <Kv k="auth" v={result.auth_mode} />
              {/* Which configuration was under test, in the backend's own words.
                  "nothing" is its answer when it refused to run one — a refusal
                  is a result, and it is not a pass. */}
              <Kv k="tested" v={result.tested} />
            </dl>
            {result.ok && result.sample && (
              <pre className="mono mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words border border-hair bg-surface2 p-2 text-[11px] text-text2">{result.sample}</pre>
            )}
            {!result.ok && (
              // Verbatim. A summarised provider error is a paraphrase of the one
              // fact the operator needs to act on.
              <pre className="mono mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words border border-sev-critical-line bg-surface2 p-2 text-[11px] text-sev-critical">
                {result.error || "The backend reported the call as failed without saying why."}
              </pre>
            )}
          </div>
          );
        })()}
      </div>
    </div>
  );
}

function Kv({ k, v }: { k: string; v?: string | null }) {
  // A missing field prints as "not reported", never as a blank that reads like
  // an answer.
  return (
    <div className="min-w-0">
      <span className="text-text3">{k} </span>
      <span className={cn("break-all", !v && "text-text3")}>{v || "not reported"}</span>
    </div>
  );
}

// ───────────────────────────────────────────────────────────────────────────

function Field({ label, htmlFor, hint, children }: {
  label: string; htmlFor: string; hint?: string; children: ReactNode;
}) {
  const hintId = hint ? `${htmlFor}-hint` : undefined;
  // The hint is genuinely part of the control's label -- half of these say what
  // a field will be REFUSED for -- so it is associated rather than merely placed
  // nearby: a screen reader announces it with the input, not two stops later.
  const control = hintId && isValidElement(children)
    ? cloneElement(children as ReactElement<{ "aria-describedby"?: string }>, { "aria-describedby": hintId })
    : children;
  return (
    <div className="space-y-1.5">
      <label htmlFor={htmlFor} className="label block">{label}</label>
      {control}
      {hint && <p id={hintId} className="max-w-2xl text-[11.5px] leading-relaxed text-text3">{hint}</p>}
    </div>
  );
}
