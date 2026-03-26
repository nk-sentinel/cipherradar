// Package fingerprint computes stable identity fingerprints for scan findings
// so that the same cryptographic usage produces the same fingerprint across
// scans even when surrounding code changes (variable renames, reformatting,
// comment edits). See ADR-034.
package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// extToLanguage maps file extensions to canonical language names used for
// normalization. T1 languages (Java, Python, Go, JS/TS) get full variable
// normalization; others get basic normalization only.
var extToLanguage = map[string]string{
	".java":  "java",
	".py":    "python",
	".pyw":   "python",
	".go":    "go",
	".js":    "javascript",
	".jsx":   "javascript",
	".ts":    "javascript",
	".tsx":   "javascript",
	".mjs":   "javascript",
	".cjs":   "javascript",
	".rs":    "rust",
	".c":     "cpp",
	".cpp":   "cpp",
	".cc":    "cpp",
	".cxx":   "cpp",
	".h":     "cpp",
	".hpp":   "cpp",
	".cs":    "csharp",
	".rb":    "ruby",
	".swift": "swift",
	".kt":    "kotlin",
	".kts":   "kotlin",
	".php":   "php",
	".dart":  "dart",
}

// LanguageFromPath returns the canonical language name for a file path based
// on its extension. Returns empty string for unrecognized extensions.
func LanguageFromPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return extToLanguage[ext]
}

// Regex patterns used for normalization. Compiled once at package init.
var (
	// Block comments: /* ... */ (non-greedy, may span lines)
	reBlockComment = regexp.MustCompile(`/\*[\s\S]*?\*/`)
	// Single-line // comments (to end of line)
	reLineComment = regexp.MustCompile(`//[^\n]*`)
	// Hash comments (Python, Ruby, etc.) — to end of line
	reHashComment = regexp.MustCompile(`#[^\n]*`)
	// Double-quoted strings (handles escaped quotes)
	reDoubleQuotedStr = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	// Single-quoted strings (handles escaped quotes)
	reSingleQuotedStr = regexp.MustCompile(`'(?:\\.|[^'\\])*'`)
	// Backtick template strings (JS/Go)
	reBacktickStr = regexp.MustCompile("`[^`]*`")
	// Hex numeric literals: 0x... (must come before general number pattern)
	reHexNum = regexp.MustCompile(`\b0[xX][0-9a-fA-F]+\b`)
	// Float numeric literals: digits with decimal point
	reFloatNum = regexp.MustCompile(`\b\d+\.\d+\b`)
	// Integer numeric literals
	reIntNum = regexp.MustCompile(`\b\d+\b`)
	// Consecutive whitespace (including newlines)
	reWhitespace = regexp.MustCompile(`\s+`)

	// Go short declaration: name := or name, name :=
	reGoShortDecl = regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*:=`)
	// JS/TS: var/let/const keyword before variable name
	reJSVarKeyword = regexp.MustCompile(`\b(?:var|let|const)\s+`)

	// Java-style typed declaration: TypeName varName = (also matches generics like Map<K,V>)
	// The type name starts with uppercase. We replace the whole "Type varName =" with "_VAR_ =".
	reJavaTypedDecl = regexp.MustCompile(`\b[A-Z]\w*(?:<[^>]*>)?\s+[a-z_]\w*\s*=`)

	// A bare identifier (lowercase or underscore leading) at a word boundary.
	// The \b prevents matching inside uppercase-leading identifiers like "Cipher".
	reBareIdent = regexp.MustCompile(`\b[a-z_]\w*`)
)

// keywords that should never be replaced with _VAR_.
var keywords = map[string]bool{
	// Control flow
	"if": true, "else": true, "for": true, "while": true, "do": true,
	"return": true, "break": true, "continue": true, "switch": true,
	"case": true, "default": true, "goto": true,
	// Declarations
	"class": true, "def": true, "func": true, "function": true,
	"import": true, "from": true, "package": true, "interface": true,
	"struct": true, "enum": true, "type": true, "extends": true,
	"implements": true, "abstract": true, "final": true, "static": true,
	"public": true, "private": true, "protected": true, "internal": true,
	// Values/literals
	"true": true, "false": true, "nil": true, "null": true,
	"undefined": true,
	// Object references
	"new": true, "this": true, "self": true, "super": true,
	// Exception handling
	"try": true, "catch": true, "throw": true, "throws": true,
	"finally": true, "except": true, "raise": true,
	// Other
	"void": true, "var": true, "let": true, "const": true, "val": true,
	"async": true, "await": true, "yield": true, "with": true, "as": true,
	"in": true, "is": true, "not": true, "and": true, "or": true,
}

// Normalize applies language-aware normalization to a code snippet, producing
// a stable signature that is resilient to cosmetic code changes.
//
// Normalization steps (in order):
//  1. Strip block comments
//  2. Strip single-line comments
//  3. Collapse whitespace to single spaces
//  4. Normalize string literals to _STR_
//  5. Normalize numeric literals to _NUM_
//  6. Normalize variable names to _VAR_
//  7. Clean up spacing and trim
func Normalize(snippet string, language string) string {
	if snippet == "" {
		return ""
	}

	s := snippet

	// Step 1: Strip block comments (/* ... */)
	s = reBlockComment.ReplaceAllString(s, "")

	// Step 2: Strip line comments
	s = reLineComment.ReplaceAllString(s, "")
	// For languages that use # comments
	if language == "python" || language == "ruby" || language == "" {
		s = reHashComment.ReplaceAllString(s, "")
	}

	// Step 3: Collapse all whitespace first (including newlines) to single space,
	// then trim. This makes subsequent regex patterns simpler.
	s = reWhitespace.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)

	// Step 4: Normalize string literals to _STR_
	s = reDoubleQuotedStr.ReplaceAllString(s, "_STR_")
	s = reSingleQuotedStr.ReplaceAllString(s, "_STR_")
	s = reBacktickStr.ReplaceAllString(s, "_STR_")

	// Step 5: Normalize numeric literals to _NUM_
	s = reHexNum.ReplaceAllString(s, "_NUM_")
	s = reFloatNum.ReplaceAllString(s, "_NUM_")
	s = reIntNum.ReplaceAllString(s, "_NUM_")

	// Step 6: Normalize variable names based on language.
	s = normalizeVars(s, language)

	// Step 7: Clean up — collapse any double spaces, normalize paren spacing.
	s = reWhitespace.ReplaceAllString(s, " ")
	s = cleanupSpacing(s)
	s = strings.TrimSpace(s)

	return s
}

// cleanupSpacing removes extraneous spaces inside parentheses and around commas.
func cleanupSpacing(s string) string {
	s = strings.ReplaceAll(s, "( ", "(")
	s = strings.ReplaceAll(s, " )", ")")
	s = strings.ReplaceAll(s, " ,", ",")
	return s
}

// normalizeVars replaces variable names with _VAR_ based on language-specific
// patterns and a general bare-identifier heuristic.
func normalizeVars(s string, language string) string {
	switch language {
	case "go":
		// Go: handle := short declarations first, replacing LHS names
		s = replaceGoVars(s)
		// Then normalize remaining bare idents that are not API calls
		s = normalizeBareIdents(s)
	case "javascript":
		// JS/TS: strip var/let/const keywords
		s = reJSVarKeyword.ReplaceAllString(s, "")
		s = normalizeBareIdents(s)
	case "java", "kotlin", "dart", "csharp", "cpp":
		// Handle typed declarations: TypeName varName = → _VAR_ =
		s = reJavaTypedDecl.ReplaceAllString(s, "_VAR_ =")
		s = normalizeBareIdents(s)
	default:
		// Python and all others: normalize bare idents
		s = normalizeBareIdents(s)
	}
	return s
}

// replaceGoVars normalizes Go short variable declarations (name := ...).
func replaceGoVars(s string) string {
	return reGoShortDecl.ReplaceAllStringFunc(s, func(match string) string {
		idx := strings.Index(match, ":=")
		if idx < 0 {
			return match
		}
		names := match[:idx]
		parts := strings.Split(names, ",")
		vars := make([]string, len(parts))
		for i := range parts {
			vars[i] = "_VAR_"
		}
		return strings.Join(vars, ", ") + " :="
	})
}

// normalizeBareIdents replaces bare lowercase identifiers with _VAR_ unless
// they are:
//   - keywords
//   - preceded by a dot (method/field access like .getInstance)
//   - followed by a dot (package/module prefix like hashlib.sha256)
//   - followed by an open paren (function call like getInstance(...))
//   - our sentinel tokens (_STR_, _NUM_, _VAR_)
func normalizeBareIdents(s string) string {
	// Process the string by finding all matches and building result.
	matches := reBareIdent.FindAllStringIndex(s, -1)
	if len(matches) == 0 {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	prev := 0

	for _, m := range matches {
		start, end := m[0], m[1]
		ident := s[start:end]

		// Write everything before this match
		b.WriteString(s[prev:start])
		prev = end

		// Check if this should be preserved
		if shouldPreserve(s, ident, start, end) {
			b.WriteString(ident)
		} else {
			b.WriteString("_VAR_")
		}
	}
	// Write remainder
	b.WriteString(s[prev:])

	return b.String()
}

// shouldPreserve returns true if the identifier at position [start:end] in s
// should NOT be replaced with _VAR_.
func shouldPreserve(s string, ident string, start int, end int) bool {
	// Our sentinel tokens
	if ident == "_STR_" || ident == "_NUM_" || ident == "_VAR_" {
		return true
	}

	// Keywords
	if keywords[ident] {
		return true
	}

	// Preceded by dot: .methodName — this is a method/field access on an object,
	// which is an API name we want to preserve.
	if start > 0 && s[start-1] == '.' {
		return true
	}

	// Followed by dot: packageName. — this is a package/module prefix.
	if end < len(s) && s[end] == '.' {
		return true
	}

	// Followed by open paren: functionCall( — this is a function call.
	if end < len(s) && s[end] == '(' {
		return true
	}

	return false
}

// ComputeFingerprint computes a stable SHA-256 identity fingerprint for a
// finding and sets both the Fingerprint and NormalizedSignature fields.
// The language parameter is the canonical language name (e.g. "java", "python").
// If language is empty, it is inferred from the finding's file path.
//
// Formula: SHA256(rule_id + ":" + file_path + ":" + normalized_code_signature)
func ComputeFingerprint(f *types.Finding, language string) string {
	if language == "" {
		language = LanguageFromPath(f.Location.File)
	}

	normalized := Normalize(f.Location.Snippet, language)
	f.NormalizedSignature = normalized

	input := f.RuleID + ":" + f.Location.File + ":" + normalized
	hash := sha256.Sum256([]byte(input))
	fp := fmt.Sprintf("%x", hash)
	f.Fingerprint = fp

	return fp
}
