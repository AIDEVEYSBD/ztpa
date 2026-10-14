"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

type Theme = "dark" | "light";
const ThemeCtx = createContext<{ theme: Theme; toggle: () => void }>({ theme: "dark", toggle: () => {} });

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const saved = (localStorage.getItem("npr-theme") as Theme) || "dark";
    setTheme(saved);
    document.documentElement.setAttribute("data-theme", saved);
  }, []);

  const toggle = () =>
    setTheme((t) => {
      const next = t === "dark" ? "light" : "dark";
      localStorage.setItem("npr-theme", next);
      document.documentElement.setAttribute("data-theme", next);
      return next;
    });

  return <ThemeCtx.Provider value={{ theme, toggle }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);

export function ThemeToggle({ className = "" }: { className?: string }) {
  const { theme, toggle } = useTheme();
  return (
    <div className={`inline-flex items-center gap-px rounded-sm border border-line bg-raise p-px ${className}`}>
      {(["light", "dark"] as const).map((t) => (
        <button
          key={t}
          type="button"
          onClick={() => { if (theme !== t) toggle(); }}
          aria-pressed={theme === t}
          aria-label={`${t} theme`}
          title={`${t} theme`}
          className={`focusable cursor-pointer rounded-xs px-2 py-1 text-[11px] transition-colors duration-100 ${
            theme === t ? "bg-surface text-fg" : "text-faint hover:text-dim"
          }`}
        >
          {t === "light" ? <Sun size={13} /> : <Moon size={13} />}
        </button>
      ))}
    </div>
  );
}
