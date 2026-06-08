package jsluice

import (
	"fmt"
	"os"
	"sync"

	"m31labs.dev/arbiter"
)

var defaultSecretClassifier secretClassifier = newArbiterSecretClassifier()

// externalClassifierCache memoizes path -> compiled classifier (or load error)
// so AnalyzeFiles over many inputs compiles an external pack at most once.
var externalClassifierCache sync.Map

type cachedClassifier struct {
	classifier secretClassifier
	err        error
}

// secretClassifierForPath returns the classifier for a given Options.SecretRulesPath.
// Empty path -> the embedded default. A non-empty path that cannot be read or
// compiled is a hard error (a buyer pointing at a broken pack must be told).
func secretClassifierForPath(path string) (secretClassifier, error) {
	if path == "" {
		return defaultSecretClassifier, nil
	}
	if v, ok := externalClassifierCache.Load(path); ok {
		c := v.(cachedClassifier)
		return c.classifier, c.err
	}
	var entry cachedClassifier
	source, err := os.ReadFile(path)
	if err != nil {
		entry.err = fmt.Errorf("load secret rules %q: %w", path, err)
	} else if cls, cerr := newArbiterSecretClassifierFromSource(source); cerr != nil {
		entry.err = fmt.Errorf("compile secret rules %q: %w", path, cerr)
	} else {
		entry.classifier = cls
	}
	externalClassifierCache.Store(path, entry)
	return entry.classifier, entry.err
}

type secretClassifier interface {
	Classify(secretCandidate) ([]secretMatch, error)
}

type arbiterSecretClassifier struct {
	once     sync.Once
	program  *arbiter.Program
	initErr  error
	fallback goSecretClassifier
}

type goSecretClassifier struct{}

func newArbiterSecretClassifier() *arbiterSecretClassifier {
	return &arbiterSecretClassifier{}
}

// newArbiterSecretClassifierFromSource compiles an external pack eagerly so a
// load/compile failure surfaces immediately rather than at first Classify.
func newArbiterSecretClassifierFromSource(source []byte) (*arbiterSecretClassifier, error) {
	program, err := arbiter.Compile(source)
	if err != nil {
		return nil, err
	}
	return &arbiterSecretClassifier{program: program}, nil
}

func (c *arbiterSecretClassifier) Classify(candidate secretCandidate) ([]secretMatch, error) {
	c.once.Do(func() {
		if c.program != nil {
			return // pre-compiled external pack; do not overwrite with embedded rules
		}
		source, err := secretRulesFS.ReadFile("rules/secrets.arb")
		if err != nil {
			c.initErr = err
			return
		}
		c.program, c.initErr = arbiter.Compile(source)
	})
	if c.initErr != nil || c.program == nil {
		return c.fallback.Classify(candidate)
	}
	ctx := map[string]any{
		"candidate": map[string]any{
			"value":       candidate.Value,
			"context":     candidate.Context,
			"length":      len(candidate.Value),
			"entropy":     shannonEntropy(candidate.Value),
			"recoveredBy": candidate.RecoveredBy,
			"placeholder": isPlaceholderSecretCandidate(candidate.Value, candidate.Context),
		},
	}
	matched, err := arbiter.Eval(c.program, arbiter.DataFromMap(ctx, c.program))
	if err != nil {
		return nil, err
	}
	out := make([]secretMatch, 0, len(matched))
	for _, match := range matched {
		if match.Action != "Secret" {
			continue
		}
		class, ok := stringParam(match.Params, "class")
		if !ok {
			return nil, fmt.Errorf("arbiter rule %s emitted Secret without class", match.Name)
		}
		confidence, ok := floatParam(match.Params, "confidence")
		if !ok {
			return nil, fmt.Errorf("arbiter rule %s emitted Secret without confidence", match.Name)
		}
		out = append(out, secretMatch{class: class, confidence: confidence})
	}
	return normalizeSecretMatches(out), nil
}

func (goSecretClassifier) Classify(candidate secretCandidate) ([]secretMatch, error) {
	return classifySecretWithGoRules(candidate), nil
}

func stringParam(params map[string]any, key string) (string, bool) {
	value, ok := params[key]
	if !ok {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}

func floatParam(params map[string]any, key string) (float64, bool) {
	value, ok := params[key]
	if !ok {
		return 0, false
	}
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	default:
		return 0, false
	}
}
