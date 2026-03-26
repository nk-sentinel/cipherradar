import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { CodeBlock } from '../../src/components/ui/CodeBlock';

// Mock shiki to fail, so we test the fallback
vi.mock('shiki', () => {
  return {
    createHighlighter: () => {
      throw new Error('Shiki not available');
    },
  };
});

describe('CodeBlock', () => {
  it('renders code in a pre element', () => {
    render(<CodeBlock code="const x = 1;" language="javascript" />);
    const block = screen.getByTestId('code-block');
    expect(block).toBeInTheDocument();
    expect(block.tagName).toBe('PRE');
    expect(block).toHaveTextContent('const x = 1;');
  });

  it('applies language class to code element', () => {
    render(<CodeBlock code="print('hello')" language="python" />);
    const codeEl = screen.getByTestId('code-block-code');
    expect(codeEl.className).toContain('language-python');
  });

  it('falls back to plain pre/code on error', () => {
    // shiki is mocked to throw, so it should always fallback
    render(<CodeBlock code="fn main() {}" language="rust" />);
    const block = screen.getByTestId('code-block');
    expect(block.tagName).toBe('PRE');
    expect(block).toHaveTextContent('fn main() {}');
  });

  it('renders multiline code correctly', () => {
    const code = `import java.security.*;
KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);`;
    render(<CodeBlock code={code} language="java" />);
    expect(screen.getByTestId('code-block')).toHaveTextContent('KeyPairGenerator');
  });
});
