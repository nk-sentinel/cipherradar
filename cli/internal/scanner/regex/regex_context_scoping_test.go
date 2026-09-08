package regex

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/nk-sentinel/cipherradar/cli/internal/types"
)

// scanAlgo scans content and returns only the algorithm-name findings.
func scanAlgo(t *testing.T, path, content string) []types.Finding {
	t.Helper()
	f, err := New().ScanFile(path, []byte(content))
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", path, err)
	}
	return filterByRulePrefix(f, "cbom-regex-algo-")
}

// algoLocs renders the algo findings as "name@line:col" for diagnostics.
func algoLocs(findings []types.Finding) string {
	var parts []string
	for _, f := range findings {
		parts = append(parts, fmt.Sprintf("%s@%d:%d", f.Name, f.Location.StartLine, f.Location.StartCol))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// assertAlgoAt requires exactly one finding for name, at the given line and col.
func assertAlgoAt(t *testing.T, findings []types.Finding, name string, line, col int) {
	t.Helper()
	var hits []types.Finding
	for _, f := range findings {
		if f.Name == name {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Errorf("expected exactly one %s finding, got %d: %s", name, len(hits), algoLocs(findings))
		return
	}
	if hits[0].Location.StartLine != line || hits[0].Location.StartCol != col {
		t.Errorf("%s at %d:%d, want %d:%d (all: %s)",
			name, hits[0].Location.StartLine, hits[0].Location.StartCol, line, col, algoLocs(findings))
	}
}

// assertNoAlgo requires no finding for name.
func assertNoAlgo(t *testing.T, findings []types.Finding, name string) {
	t.Helper()
	for _, f := range findings {
		if f.Name == name {
			t.Errorf("expected NO %s finding, got one at %d:%d (snippet %q)",
				name, f.Location.StartLine, f.Location.StartCol, f.Location.Snippet)
		}
	}
}

// linesOf returns the sorted, deduplicated lines a named algo was found on.
func linesOf(findings []types.Finding, name string) []int {
	seen := map[int]bool{}
	for _, f := range findings {
		if f.Name == name {
			seen[f.Location.StartLine] = true
		}
	}
	var out []int
	for l := range seen {
		out = append(out, l)
	}
	sort.Ints(out)
	return out
}

// ---------------------------------------------------------------------------
// #134 — file-type scoping (algo-name skipped on prose/data; PEM kept)
// ---------------------------------------------------------------------------

func TestAlgoSkippedOnProseAndData(t *testing.T) {
	prose := "We used MD5 and DES, then migrated to AES-256.\n"
	for _, path := range []string{
		"notes.txt", "README.md", "guide.rst", "doc.adoc", "paper.tex",
		"data.csv", "run.log", "yarn.lock", "go.sum", "vectors.golden",
		"nb.ipynb", "schema.proto", "LICENSE", "CHANGELOG", "NOTICE",
	} {
		if algo := scanAlgo(t, path, prose); len(algo) != 0 {
			t.Errorf("%s: expected 0 algo-name findings from prose, got %d %s", path, len(algo), algoLocs(algo))
		}
	}
}

func TestPEMStillDetectedInProse(t *testing.T) {
	// A leaked private key in a .txt / .md is a real finding — PEM rules must
	// keep running even though algo-name rules are suppressed there.
	content := "Here is a key we accidentally committed:\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" +
		"-----END RSA PRIVATE KEY-----\n"
	for _, path := range []string{"leak.txt", "README.md", "notes.rst"} {
		all, err := New().ScanFile(path, []byte(content))
		if err != nil {
			t.Fatalf("ScanFile(%s): %v", path, err)
		}
		if pem := filterByRulePrefix(all, "cbom-regex-pem-"); len(pem) == 0 {
			t.Errorf("%s: expected a PEM finding, got none", path)
		}
		if algo := filterByRulePrefix(all, "cbom-regex-algo-"); len(algo) != 0 {
			t.Errorf("%s: expected no algo-name findings, got %s", path, algoLocs(algo))
		}
	}
}

func TestAlgoKeptInConfig(t *testing.T) {
	conf := "ssl_protocols TLSv1.0;\ncipher DES;\n"
	algo := scanAlgo(t, "nginx.conf", conf)
	assertAlgoAt(t, algo, "TLSv1.0", 1, 15)
	assertAlgoAt(t, algo, "DES", 2, 8)
}

// ---------------------------------------------------------------------------
// #135 — comment-stripping (with exact line/column assertions)
// ---------------------------------------------------------------------------

func TestCommentedOutCodeSuppressed_LineNumbersExact(t *testing.T) {
	src := "import hashlib\n" + // 1
		"# cipher = DES.new(key)\n" + // 2  DES in a comment -> suppressed
		"x = 1\n" + // 3
		"algo = \"MD5\"  # note: SHA-1 removed\n" + // 4  MD5 in a string (kept); SHA-1 in comment (suppressed)
		"y = DES\n" // 5  real DES

	algo := scanAlgo(t, "app.py", src)

	// DES must appear ONLY on line 5, never from the line-2 comment.
	if got := linesOf(algo, "DES"); len(got) != 1 || got[0] != 5 {
		t.Errorf("DES lines = %v, want [5]  (all: %s)", got, algoLocs(algo))
	}
	assertAlgoAt(t, algo, "DES", 5, 5) // "y = DES" -> D at col 5
	assertAlgoAt(t, algo, "MD5", 4, 9) // algo = "MD5" -> M at col 9 (string preserved)
	assertNoAlgo(t, algo, "SHA-1")     // in the trailing comment
}

func TestBlockCommentMultiLineSuppressed(t *testing.T) {
	src := "code1\n" + // 1
		"/* this block\n" + // 2  block open
		"   mentions AES-256\n" + // 3  inside block
		"   and DES too */\n" + // 4  inside block + close
		"real = \"SSLv3\"\n" // 5  real protocol in a string

	algo := scanAlgo(t, "x.c", src)
	assertNoAlgo(t, algo, "AES-256")
	assertNoAlgo(t, algo, "DES")
	assertAlgoAt(t, algo, "SSLv3", 5, 9)
}

// The column test that matters most: a block comment that ends mid-line, with a
// real token AFTER it on the same line. Masking is length-preserving, so the
// token's column must be reported unchanged.
func TestBlockCommentInlineColumnPreserved(t *testing.T) {
	src := "x /* MD5 */ = DES\n" // /* MD5 */ occupies cols 3-11; DES starts at col 15
	algo := scanAlgo(t, "y.c", src)
	assertNoAlgo(t, algo, "MD5")
	assertAlgoAt(t, algo, "DES", 1, 15)
}

func TestTrailingLineCommentSuppressedRealKept(t *testing.T) {
	src := "y = DES  // legacy MD5 path\n" // real DES; MD5 in trailing // comment
	algo := scanAlgo(t, "u.go", src)
	assertAlgoAt(t, algo, "DES", 1, 5)
	assertNoAlgo(t, algo, "MD5")
}

func TestConfigHashCommentSuppressed(t *testing.T) {
	src := "# uses MD5 for legacy hashing\nhash: SHA-256\n"
	algo := scanAlgo(t, "c.yaml", src)
	assertNoAlgo(t, algo, "MD5") // in a # comment
	assertAlgoAt(t, algo, "SHA-256", 2, 7)
}

func TestSQLCommentSuppressed(t *testing.T) {
	src := "SELECT foo -- MD5 was here\nFROM t WHERE algo = 'DES'\n"
	algo := scanAlgo(t, "q.sql", src)
	assertNoAlgo(t, algo, "MD5")        // -- comment
	assertAlgoAt(t, algo, "DES", 2, 22) // 'DES' inside a string literal is kept (D at col 22)
}

func TestXMLCommentSuppressed(t *testing.T) {
	src := "<config>\n<!-- legacy DES cipher -->\n<cipher>AES-256</cipher>\n</config>\n"
	algo := scanAlgo(t, "c.xml", src)
	assertNoAlgo(t, algo, "DES")           // inside <!-- -->
	assertAlgoAt(t, algo, "AES-256", 3, 9) // <cipher>AES-256 -> A at col 9
}

// String-awareness: a comment marker that appears *inside* a string literal must
// not start a comment, and a token inside that string is still detected.
func TestCommentMarkerInsideStringNotTreatedAsComment(t *testing.T) {
	src := "s = \"x // DES\"\n" // the // is inside the string; DES is string content
	algo := scanAlgo(t, "v.go", src)
	assertAlgoAt(t, algo, "DES", 1, 11)
}

// A stray quote must not run away and mask the rest of the file: string state
// resets at end-of-line, so a later line's real token is still found.
func TestUnterminatedStringDoesNotMaskLaterLines(t *testing.T) {
	src := "a = \"oops\n" + // 1  quote not closed on this line
		"b = DES\n" // 2  must still be detected
	algo := scanAlgo(t, "w.go", src)
	assertAlgoAt(t, algo, "DES", 2, 5)
}

// ---------------------------------------------------------------------------
// Structural invariant: masking preserves length + newline positions, which is
// what guarantees reported line/column stay exact.
// ---------------------------------------------------------------------------

func TestMaskCommentsPreservesLengthAndNewlines(t *testing.T) {
	cases := []struct{ ext, in string }{
		{".go", "a // c\nb /* x\ny */ z\n"},
		{".py", "a # c\nb = 1\n"},
		{".sql", "SELECT 1 -- c\n/* x */ 2\n"},
		{".xml", "<a><!-- c -->b</a>\n"},
		{".c", "s = \"//not a comment\" // real\nq /* multi\nline */ r\n"},
		{".ini", "k=v ; c\n#c2\n"},
	}
	for _, tc := range cases {
		out := maskCommentsForAlgo([]byte(tc.in), tc.ext)
		if len(out) != len(tc.in) {
			t.Errorf("%s: length changed %d -> %d", tc.ext, len(tc.in), len(out))
			continue
		}
		for i := 0; i < len(tc.in); i++ {
			if (tc.in[i] == '\n') != (out[i] == '\n') {
				t.Errorf("%s: newline at byte %d not preserved (in=%q out=%q)", tc.ext, i, tc.in[i], out[i])
			}
		}
	}
}

func TestMaskCommentsUnknownExtIsNoOp(t *testing.T) {
	in := "x // MD5 not stripped for unknown ext"
	if out := maskCommentsForAlgo([]byte(in), ".xyz"); string(out) != in {
		t.Errorf("unknown ext should be a no-op; got %q", string(out))
	}
}

func TestShouldRunAlgoName(t *testing.T) {
	tests := []struct {
		path string
		run  bool
	}{
		{"app.py", true}, {"nginx.conf", true}, {"config.yaml", true},
		{"main.go", true}, {"lib.h", true}, {"query.sql", true},
		{"notes.txt", false}, {"README.md", false}, {"doc.rst", false},
		{"data.csv", false}, {"trace.log", false}, {"schema.proto", false},
		{"LICENSE", false}, {"README", false}, {"CHANGELOG", false},
		{"sub/dir/notes.TXT", false}, // case-insensitive ext
	}
	for _, tt := range tests {
		if got := shouldRunAlgoName(tt.path); got != tt.run {
			t.Errorf("shouldRunAlgoName(%q) = %v, want %v", tt.path, got, tt.run)
		}
	}
}
