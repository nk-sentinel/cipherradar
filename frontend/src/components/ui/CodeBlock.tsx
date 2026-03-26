import { useState, useEffect } from 'react';

interface CodeBlockProps {
  code: string;
  language: string;
  theme?: 'dark' | 'light';
}

/**
 * Syntax-highlighted code block using Shiki.
 * Falls back to plain <pre><code> if Shiki fails to load.
 */
export function CodeBlock({ code, language, theme }: CodeBlockProps): React.ReactElement {
  const [html, setHtml] = useState<string | null>(null);
  const [error, setError] = useState(false);

  // Auto-detect theme from CSS variable if not provided
  const resolvedTheme = theme ?? detectTheme();

  useEffect(() => {
    let cancelled = false;

    async function highlight() {
      try {
        const shiki = await import('shiki');
        const highlighter = await shiki.createHighlighter({
          themes: [resolvedTheme === 'dark' ? 'github-dark' : 'github-light'],
          langs: [language],
        });

        if (cancelled) return;

        const result = highlighter.codeToHtml(code, {
          lang: language,
          theme: resolvedTheme === 'dark' ? 'github-dark' : 'github-light',
        });

        setHtml(result);
      } catch {
        if (!cancelled) {
          setError(true);
        }
      }
    }

    void highlight();

    return () => {
      cancelled = true;
    };
  }, [code, language, resolvedTheme]);

  // Fallback: plain pre/code
  if (error || html === null) {
    return (
      <pre
        className="code-block"
        data-testid="code-block"
        style={{
          background: 'var(--bg-3)',
          padding: '12px',
          borderRadius: 'var(--radius)',
          overflow: 'auto',
          fontSize: '12px',
          lineHeight: '1.5',
        }}
      >
        <code className={`language-${language}`} data-testid="code-block-code">
          {code}
        </code>
      </pre>
    );
  }

  return (
    <div
      className="code-block"
      data-testid="code-block"
      style={{
        borderRadius: 'var(--radius)',
        overflow: 'auto',
        fontSize: '12px',
        lineHeight: '1.5',
      }}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

/**
 * Detect theme from document body class.
 * Dark themes: radar, midnight, terminal, phantom
 * Light themes: crystal
 */
function detectTheme(): 'dark' | 'light' {
  if (typeof document === 'undefined') return 'dark';
  const body = document.body;
  if (body.classList.contains('theme-crystal')) return 'light';
  return 'dark';
}
