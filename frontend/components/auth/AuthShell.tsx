import Link from "next/link";
import { Brand } from "@/components/ui";

export function AuthShell({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="relative grid min-h-screen place-items-center bg-canvas px-4">
      <div className="relative w-full max-w-sm">
        <div className="mb-5">
          <Link href="/" className="focusable inline-block" aria-label="Back to home"><Brand /></Link>
          <div className="mt-2 text-[11.5px] text-dim">{subtitle ?? "Network-policy risk, explained & gated"}</div>
        </div>
        <div className="overflow-hidden rounded-lg border border-line bg-surface elev-2">
          <div className="p-6">
            <h1 className="mb-4 text-[20px] font-semibold tracking-[-0.015em]">{title}</h1>
            {children}
          </div>
        </div>
        <p className="mt-4 text-center text-[10.5px] text-ghost">Engine owns the facts · AI owns the judgment</p>
      </div>
    </div>
  );
}

export function AuthInput(props: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const { label, ...rest } = props;
  return (
    <label className="block">
      <span className="mb-1.5 block text-[12.5px] font-medium text-mist">{label}</span>
      <input {...rest} className="field w-full" />
    </label>
  );
}

export function AuthBanner({ children, kind = "ok" }: { children: React.ReactNode; kind?: "ok" | "error" }) {
  return (
    <div className="relative mb-3 overflow-hidden rounded-lg border border-line bg-surface p-3 pl-4 text-[12.5px] leading-[1.55] text-dim">
      <span aria-hidden className={`absolute inset-y-0 left-0 w-[3px] ${kind === "ok" ? "bg-ok" : "bg-err"}`} />
      {children}
    </div>
  );
}
