// Package prompttpl renders operator-authored prompt templates for the LLM
// draft pipeline. A template declares its variables up front; referencing an
// undeclared variable in the user template is a validation error at save time.
// The system prompt is treated as a literal instruction; only the user template
// is variable-substituted.
package prompttpl

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// Variable is a declared substitution variable. Example feeds the dry-run
// render when no value is supplied.
type Variable struct {
	Name        string `json:"name"`
	Example     string `json:"example,omitempty"`
	Description string `json:"description,omitempty"`
}

// ValidKind reports whether k is a supported template kind.
func ValidKind(k string) bool {
	switch k {
	case "email", "sms", "landing":
		return true
	default:
		return false
	}
}

var identRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// refRe captures the leading identifier of a `{{ .Field ... }}` reference.
var refRe = regexp.MustCompile(`\{\{-?\s*\.([A-Za-z_][A-Za-z0-9_]*)`)

// declaredNames returns the set of declared variable names.
func declaredNames(vars []Variable) map[string]struct{} {
	set := make(map[string]struct{}, len(vars))
	for _, v := range vars {
		set[v.Name] = struct{}{}
	}
	return set
}

// referencedVars returns the unique, sorted top-level variables referenced in
// a template body.
func referencedVars(body string) []string {
	seen := map[string]struct{}{}
	for _, m := range refRe.FindAllStringSubmatch(body, -1) {
		seen[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ValidateVariables checks that declared variable names are valid identifiers
// and unique.
func ValidateVariables(vars []Variable) error {
	seen := map[string]struct{}{}
	for _, v := range vars {
		if !identRe.MatchString(v.Name) {
			return fmt.Errorf("invalid variable name %q (must match [A-Za-z_][A-Za-z0-9_]*)", v.Name)
		}
		if _, dup := seen[v.Name]; dup {
			return fmt.Errorf("duplicate variable %q", v.Name)
		}
		seen[v.Name] = struct{}{}
	}
	return nil
}

// ValidateUserTemplate parses the user template and rejects any referenced
// variable that is not declared.
func ValidateUserTemplate(userTemplate string, vars []Variable) error {
	if strings.TrimSpace(userTemplate) == "" {
		return fmt.Errorf("user_template is required")
	}
	if _, err := template.New("ut").Option("missingkey=zero").Parse(userTemplate); err != nil {
		return fmt.Errorf("user_template parse error: %w", err)
	}
	declared := declaredNames(vars)
	var undeclared []string
	for _, ref := range referencedVars(userTemplate) {
		if _, ok := declared[ref]; !ok {
			undeclared = append(undeclared, ref)
		}
	}
	if len(undeclared) > 0 {
		return fmt.Errorf("user_template references undeclared variable(s): %s", strings.Join(undeclared, ", "))
	}
	return nil
}

// Validate runs the full save-time validation for a template definition.
func Validate(kind, userTemplate string, vars []Variable) error {
	if !ValidKind(kind) {
		return fmt.Errorf("kind must be one of email, sms, landing")
	}
	if err := ValidateVariables(vars); err != nil {
		return err
	}
	return ValidateUserTemplate(userTemplate, vars)
}

// Render executes the user template against ctx. Missing keys render as the
// empty string (missingkey=zero), so a valid template never errors at render.
func Render(userTemplate string, ctx map[string]string) (string, error) {
	t, err := template.New("ut").Option("missingkey=zero").Parse(userTemplate)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	var sb strings.Builder
	if err := t.Execute(&sb, ctx); err != nil {
		return "", fmt.Errorf("render: %w", err)
	}
	return sb.String(), nil
}

// BuildPrompt renders the user template and prepends the literal system prompt.
func BuildPrompt(systemPrompt, userTemplate string, ctx map[string]string) (string, error) {
	rendered, err := Render(userTemplate, ctx)
	if err != nil {
		return "", err
	}
	sys := strings.TrimSpace(systemPrompt)
	if sys == "" {
		return rendered, nil
	}
	return sys + "\n\n" + rendered, nil
}

// SampleContext builds a render context from declared examples, overlaid with
// any supplied overrides (overrides for undeclared names are ignored).
func SampleContext(vars []Variable, overrides map[string]string) map[string]string {
	ctx := make(map[string]string, len(vars))
	for _, v := range vars {
		ctx[v.Name] = v.Example
	}
	for _, v := range vars {
		if ov, ok := overrides[v.Name]; ok {
			ctx[v.Name] = ov
		}
	}
	return ctx
}
