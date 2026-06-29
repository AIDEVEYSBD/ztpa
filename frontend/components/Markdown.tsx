import Markdown from "react-markdown";

/** Renders LLM/markdown output with the app's type scale (no raw markdown leaking). */
export function Prose({ children, className = "" }: { children: string; className?: string }) {
  return (
    <div className={`text-[13px] leading-relaxed text-text2
      [&_h1]:mb-2 [&_h1]:mt-4 [&_h1]:text-[18px] [&_h1]:font-bold [&_h1]:text-text
      [&_h2]:mb-2 [&_h2]:mt-4 [&_h2]:text-[15px] [&_h2]:font-bold [&_h2]:text-text
      [&_h3]:mb-1 [&_h3]:mt-3 [&_h3]:text-[13px] [&_h3]:font-bold [&_h3]:text-text
      [&_p]:my-2 [&_p]:text-text2
      [&_ul]:my-2 [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:my-2 [&_ol]:list-decimal [&_ol]:pl-5
      [&_li]:my-0.5 [&_li]:text-text2 [&_li]:marker:text-accent-fg
      [&_strong]:font-bold [&_strong]:text-text
      [&_code]:mono [&_code]:text-[12px] [&_code]:text-accent-fg [&_code]:bg-sunk [&_code]:border [&_code]:border-border [&_code]:px-1
      [&_a]:text-accent-fg [&_a]:underline [&_a]:underline-offset-2
      [&_blockquote]:my-2 [&_blockquote]:border-l-2 [&_blockquote]:border-border [&_blockquote]:pl-3 [&_blockquote]:text-text3
      [&_table]:my-2 [&_table]:w-full [&_table]:border-collapse [&_table]:text-[12px]
      [&_th]:border [&_th]:border-border [&_th]:bg-sunk [&_th]:px-2 [&_th]:py-1 [&_th]:text-left [&_th]:font-bold [&_th]:text-text3
      [&_td]:border [&_td]:border-border [&_td]:px-2 [&_td]:py-1 [&_td]:text-text2
      [&_hr]:my-3 [&_hr]:border-border ${className}`}>
      <Markdown>{children}</Markdown>
    </div>
  );
}
