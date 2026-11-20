package hygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stdoutOwner is the one file that may name os.Stdout: it hands stdout to the
// audit sink.
const stdoutOwner = "cmd/podcertificate-signer/main.go"

// TestNothingElseWritesToStdout keeps stdout for the issuance audit records.
// A consumer reads every stdout line as one JSON audit record, so any other
// line on stdout breaks it. The operational log goes to stderr.
//
// The scan parses every Go file under cmd/ and internal/ and fails on a call
// to fmt.Print, fmt.Printf or fmt.Println and on any use of os.Stdout. The
// only exception is one os.Stdout in stdoutOwner.
func TestNothingElseWritesToStdout(t *testing.T) {
	root := repoRoot(t)
	stdoutUses := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			for _, use := range stdoutWrites(t, path) {
				if use.name == "os.Stdout" && rel == stdoutOwner {
					stdoutUses++
					continue
				}
				t.Errorf("%s:%d uses %s: only the audit sink may write to stdout", rel, use.line, use.name)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if stdoutUses != 1 {
		t.Errorf("%s uses os.Stdout %d times, want 1: the audit sink wiring", stdoutOwner, stdoutUses)
	}
}

// stdoutUse is one reference to a stdout writer in a source file.
type stdoutUse struct {
	name string
	line int
}

// stdoutWrites returns every reference in the Go file at path to
// fmt.Print, fmt.Printf, fmt.Println or os.Stdout. It resolves the local
// names of the fmt and os imports, and comments do not count.
func stdoutWrites(t *testing.T, path string) []stdoutUse {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	local := map[string]string{}
	for _, imp := range file.Imports {
		importPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil || (importPath != "fmt" && importPath != "os") {
			continue
		}
		name := importPath
		if imp.Name != nil {
			name = imp.Name.Name
		}
		local[name] = importPath
	}
	forbidden := map[string]bool{"fmt.Print": true, "fmt.Printf": true, "fmt.Println": true, "os.Stdout": true}

	var uses []stdoutUse
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		importPath, ok := local[pkg.Name]
		if !ok {
			return true
		}
		if name := importPath + "." + sel.Sel.Name; forbidden[name] {
			uses = append(uses, stdoutUse{name: name, line: fset.Position(sel.Pos()).Line})
		}
		return true
	})
	return uses
}
