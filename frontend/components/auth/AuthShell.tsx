import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export function AuthShell({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="relative grid min-h-screen place-items-center px-4">
      <div className="grid-bg pointer-events-none absolute inset-0" />
      <div className="relative w-full max-w-sm">
        <div className="mb-5 flex items-center gap-3">
          <div className="grid h-11 w-11 shrink-0 place-items-center bg-accent-ink">
            <ShieldCheck size={22} className="text-accent" />
          </div>
          <div className="leading-tight">
            <div className="text-sm font-semibold">ZeroTrust Policy Advisor</div>
            <div className="text-xs text-muted">{subtitle ?? "Network-policy risk, explained & gated"}</div>
          </div>
        </div>
        <div className="panel p-6">
          <h1 className="mb-4 text-lg font-bold">{title}</h1>
          {children}
        </div>
        <p className="mt-4 text-center text-[11px] text-muted">Engine owns the facts · AI owns the judgment</p>
      </div>
    </div>
  );
}

export function AuthInput(props: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const { label, ...rest } = props;
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-muted">{label}</span>
      <input {...rest}
        className="field w-full" />
    </label>
  );
}

export function AuthBanner({ children, kind = "ok" }: { children: React.ReactNode; kind?: "ok" | "error" }) {
  const c = kind === "ok" ? "border-sev-low-line bg-sev-low-bg text-sev-low" : "border-sev-critical-line bg-sev-critical-bg text-sev-critical";
  return <div className={`mb-3 rounded-lg border p-2.5 text-xs ${c}`}>{children}</div>;
}

export function DevLink({ href }: { href: string }) {
  return (
    <div className="mt-3 rounded-lg border border-accent bg-accent-soft p-2.5 text-xs">
      <div className="mb-1 font-semibold text-text2">Dev link (Resend not configured)</div>
      <Link href={href} className="break-all text-ink underline">{href}</Link>
    </div>
  );
}
