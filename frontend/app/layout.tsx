import "./globals.css";
import type { Metadata } from "next";
import { Providers } from "@/components/Providers";

export const metadata: Metadata = {
  title: "ZeroTrust Policy Advisor",
  description: "One unified, cross-tool view of network-policy risk - explained, prioritized, and gated.",
};

const noFlash = `(function(){try{var t=localStorage.getItem('ztpa-theme')||'dark';document.documentElement.setAttribute('data-theme',t);}catch(e){document.documentElement.setAttribute('data-theme','dark');}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: noFlash }} /></head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
