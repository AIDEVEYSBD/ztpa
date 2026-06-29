import Link from "next/link";
import { Brand, SpectrumLine } from "@/components/ui";

export function AuthShell({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="bg-aurora relative grid min-h-screen place-items-center px-4">
      <div className="relative w-full max-w-sm">
        <div className="mb-5">
          <Link href="/" className="inline-block" aria-label="Back to home"><Brand /></Link>
          <div className="mt-2 text-[11px] text-text2">{subtitle ?? "Network-policy risk, explained & gated"}</div>
        </div>
        <div className="panel glow-accent relative overflow-hidden">
          <SpectrumLine thin className="absolute inset-x-0 top-0" />
          <div className="p-6">
            <h1 className="mb-4 text-lg font-bold">{title}</h1>
            {children}
          </div>
        </div>
        <p className="mt-4 text-center text-[11px] text-text3">Engine owns the facts · AI owns the judgment</p>
      </div>
    </div>
  );
}

export function AuthInput(props: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const { label, ...rest } = props;
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-text2">{label}</span>
      <input {...rest} className="field w-full" />
    </label>
  );
}

export function AuthBanner({ children, kind = "ok" }: { children: React.ReactNode; kind?: "ok" | "error" }) {
  const c = kind === "ok"
    ? "border-ok-line bg-ok-bg text-ok"
    : "border-sev-critical-line bg-sev-critical-bg text-sev-critical";
  return <div className={`mb-3 border p-2.5 text-xs ${c}`}>{children}</div>;
}

export function DevLink({ href }: { href: string }) {
  return (
    <div className="mt-3 border border-accent bg-accent-soft p-2.5 text-xs">
      <div className="mb-1 font-semibold text-text2">Dev link (Resend not configured)</div>
      <Link href={href} className="break-all text-accent-fg underline">{href}</Link>
    </div>
  );
}
