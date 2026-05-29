package diagnostic

import "github.com/goccy/go-yaml/token"

type Error struct {
	Token   *token.Token
	RuleID  string
	Message string
	// ExtraContexts holds non-ancestor tokens to display as additional context
	// (MarkerNone, no text). Ancestor breadcrumbs are computed automatically
	// by the renderer from the Token's position.
	ExtraContexts []*token.Token
	// Markers holds additional tokens to highlight with MarkerCaret (no text).
	Markers []*token.Token
	// Why overrides the rule-level Explainer.Why() for this specific diagnostic.
	// When non-empty, the markdown renderer uses this instead of the rule's Why().
	Why string
	// Fix overrides the rule-level Explainer.Fix() for this specific diagnostic.
	// When non-empty, the markdown renderer uses this instead of the rule's Fix().
	Fix string
	// Ref overrides the default rule README URL for this specific diagnostic.
	// When non-empty, renderers use this URL instead of the
	// rules/<RuleID>/README.md default. Used by rules whose RuleID does not map
	// to a repository README (e.g. shellcheck/SC2086 links to the shellcheck wiki).
	Ref string
}

func (e *Error) Error() string { return e.Message }
