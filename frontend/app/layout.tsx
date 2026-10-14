import "./globals.css";
import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { Providers } from "@/components/Providers";
import { Material } from "@/components/ui/Material";

const plex = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Network Policy Reviewer",
  description: "One unified, cross-tool view of network-policy risk - explained, prioritized, and gated.",
};

// Runs before paint so the themed tokens are in place on first frame.
const noFlash = `(function(){try{var t=localStorage.getItem('npr-theme')||'dark';document.documentElement.setAttribute('data-theme',t);var a=localStorage.getItem('npr-accent');if(a==='off'){document.documentElement.setAttribute('data-accent','off');}}catch(e){document.documentElement.setAttribute('data-theme','dark');}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" className={`${plex.variable} ${plexMono.variable}`} suppressHydrationWarning>
      <head><script dangerouslySetInnerHTML={{ __html: noFlash }} /></head>
      <body>
        <Material />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
