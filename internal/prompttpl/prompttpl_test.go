package prompttpl

import "testing"

func vars(names ...string) []Variable {
	out := make([]Variable, 0, len(names))
	for _, n := range names {
		out = append(out, Variable{Name: n})
	}
	return out
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		body    string
		vars    []Variable
		wantErr bool
	}{
		{"ok all declared", "email", "Hi {{.FirstName}} at {{.Company}}", vars("FirstName", "Company"), false},
		{"ok no vars", "sms", "Static reminder text", nil, false},
		{"undeclared var", "email", "Hi {{.FirstName}}", vars("Company"), true},
		{"one undeclared among declared", "email", "{{.A}} {{.B}} {{.C}}", vars("A", "B"), true},
		{"empty body", "email", "   ", vars("A"), true},
		{"bad kind", "phishlet", "hello", nil, true},
		{"syntax error", "email", "Hi {{.FirstName", vars("FirstName"), true},
		{"dup var", "email", "{{.A}}", []Variable{{Name: "A"}, {Name: "A"}}, true},
		{"bad var name", "email", "ok", []Variable{{Name: "1bad"}}, true},
		{"whitespace in ref", "email", "Hi {{- .FirstName }}", vars("FirstName"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Validate(c.kind, c.body, c.vars)
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate(%q) err=%v, wantErr=%v", c.body, err, c.wantErr)
			}
		})
	}
}

func TestReferencedVars(t *testing.T) {
	got := referencedVars("{{.B}} text {{ .A }} and {{.A}} again {{- .C}}")
	want := []string{"A", "B", "C"} // unique + sorted
	if len(got) != len(want) {
		t.Fatalf("referencedVars=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("referencedVars=%v want %v", got, want)
		}
	}
}

func TestRender(t *testing.T) {
	cases := []struct {
		name string
		body string
		ctx  map[string]string
		want string
	}{
		{"substitutes", "Hi {{.FirstName}}", map[string]string{"FirstName": "Dana"}, "Hi Dana"},
		{"missing key is empty", "Hi {{.Missing}}!", map[string]string{}, "Hi !"},
		{"multiple", "{{.A}}-{{.B}}", map[string]string{"A": "x", "B": "y"}, "x-y"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Render(c.body, c.ctx)
			if err != nil {
				t.Fatalf("Render error: %v", err)
			}
			if got != c.want {
				t.Fatalf("Render=%q want %q", got, c.want)
			}
		})
	}
}

func TestBuildPrompt(t *testing.T) {
	got, err := BuildPrompt("SYSTEM RULES", "Body for {{.Name}}", map[string]string{"Name": "Acme"})
	if err != nil {
		t.Fatalf("BuildPrompt error: %v", err)
	}
	want := "SYSTEM RULES\n\nBody for Acme"
	if got != want {
		t.Fatalf("BuildPrompt=%q want %q", got, want)
	}

	// Empty system prompt -> just the rendered body.
	got, _ = BuildPrompt("  ", "Body only", nil)
	if got != "Body only" {
		t.Fatalf("BuildPrompt (no system)=%q", got)
	}
}

func TestSampleContext(t *testing.T) {
	vs := []Variable{{Name: "A", Example: "exA"}, {Name: "B", Example: "exB"}}
	ctx := SampleContext(vs, map[string]string{"B": "override", "Undeclared": "ignored"})
	if ctx["A"] != "exA" {
		t.Fatalf("A=%q want exA (example)", ctx["A"])
	}
	if ctx["B"] != "override" {
		t.Fatalf("B=%q want override", ctx["B"])
	}
	if _, ok := ctx["Undeclared"]; ok {
		t.Fatalf("undeclared override should be ignored")
	}
}
