import Markdown from "react-markdown";

/** Renders LLM/markdown output with the app's type scale (no raw markdown leaking). */
export function Prose({ children, className = "" }: { children: string; className?: string }) {
  return (
    <div className={`text-[13px] leading-relaxed
      [&_h1]:mb-2 [&_h1]:mt-4 [&_h1]:text-[18px] [&_h1]:font-bold [&_h1]:text-text
      [&_h2]:mb-2 [&_h2]:mt-4 [&_h2]:text-[15px] [&_h2]:font-bold [&_h2]:text-text
      [&_h3]:mb-1 [&_h3]:mt-3 [&_h3]:text-[13px] [&_h3]:font-bold [&_h3]:text-text
      [&_p]:my-2 [&_ul]:my-2 [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:my-2 [&_ol]:list-decimal [&_ol]:pl-5
      [&_li]:my-0.5 [&_strong]:font-bold [&_strong]:text-text [&_code]:mono [&_code]:text-[12px]
      [&_code]:bg-surfaceHover [&_code]:px-1 [&_a]:text-text [&_a]:underline ${className}`}>
      <Markdown>{children}</Markdown>
    </div>
  );
}
