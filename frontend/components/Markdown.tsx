import Markdown from "react-markdown";

/** Renders LLM/markdown output with the app's type scale (no raw markdown leaking). */
export function Prose({ children, className = "" }: { children: string; className?: string }) {
  return (
    <div className={`text-[13px] leading-[1.6] text-dim
      [&_h1]:mt-4 [&_h1]:mb-2 [&_h1]:text-[17px] [&_h1]:font-semibold [&_h1]:tracking-[-0.015em] [&_h1]:text-fg
      [&_h2]:mt-4 [&_h2]:mb-2 [&_h2]:text-[15px] [&_h2]:font-semibold [&_h2]:tracking-[-0.005em] [&_h2]:text-fg
      [&_h3]:mt-3 [&_h3]:mb-1 [&_h3]:text-[13.5px] [&_h3]:font-semibold [&_h3]:text-fg
      [&_p]:my-1 [&_p]:text-dim
      [&_ul]:my-1 [&_ul]:list-disc [&_ul]:pl-4 [&_ol]:my-1 [&_ol]:list-decimal [&_ol]:pl-4
      [&_li]:my-0.5 [&_li]:text-dim [&_li]:marker:text-faint
      [&_strong]:font-semibold [&_strong]:text-fg
      [&_code]:rounded-sm [&_code]:bg-raise [&_code]:px-1 [&_code]:font-mono [&_code]:text-[11px] [&_code]:text-fg
      [&_pre]:rounded-sm [&_pre]:border [&_pre]:border-line [&_pre]:bg-raise [&_pre]:px-2 [&_pre]:py-1.5 [&_pre]:font-mono [&_pre]:text-[11px]
      [&_a]:text-fg [&_a]:underline [&_a]:underline-offset-2
      [&_blockquote]:my-2 [&_blockquote]:border-l-2 [&_blockquote]:border-line-strong [&_blockquote]:pl-3 [&_blockquote]:text-faint
      [&_table]:my-2 [&_table]:w-full [&_table]:border-collapse [&_table]:text-[11.5px]
      [&_th]:border-b [&_th]:border-line [&_th]:bg-raise/60 [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:text-[10.5px] [&_th]:font-medium [&_th]:text-faint
      [&_td]:border-b [&_td]:border-line [&_td]:px-3 [&_td]:py-2 [&_td]:text-dim
      [&_hr]:my-3 [&_hr]:border-line ${className}`}>
      <Markdown>{children}</Markdown>
    </div>
  );
}
