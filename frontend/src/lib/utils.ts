/**
 * Concatenate class names, filtering out falsy values.
 */
export function cn(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(' ');
}

/**
 * Extract initials from a name string (up to 2 characters).
 */
export function getInitials(name: string): string {
  return name
    .split(' ')
    .map((part) => part.charAt(0))
    .join('')
    .toUpperCase()
    .slice(0, 2);
}

/**
 * Format a number with comma separators.
 */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}
