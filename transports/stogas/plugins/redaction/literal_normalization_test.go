package redaction

import (
	"reflect"
	"slices"
	"testing"
)

func TestLiteralNormalizationPreservesEveryOptionCombination(t *testing.T) {
	var choices []Literal
	for _, ignoreCase := range []bool{false, true} {
		for _, fuzzy := range []bool{false, true} {
			for _, wholeWord := range []bool{false, true} {
				if !fuzzy || wholeWord {
					choices = append(choices, Literal{Text: "ProjectAurora", IgnoreCase: ignoreCase, Fuzzy: fuzzy, WholeWord: &wholeWord})
				}
			}
		}
	}
	// This oracle describes the accepted match set independently of the
	// normalization algorithm and its choice of retained representatives.
	accepts := func(rules []Literal, sameCase bool, edits int, boundary bool) bool {
		for _, rule := range rules {
			if (rule.IgnoreCase || sameCase) && (edits == 0 || rule.Fuzzy && edits == 1) &&
				(rule.WholeWord != nil && !*rule.WholeWord || boundary) {
				return true
			}
		}
		return false
	}
	for mask := 0; mask < 1<<len(choices); mask++ {
		var selected []Literal
		for i, rule := range choices {
			if mask&(1<<i) != 0 {
				selected = append(selected, rule)
			}
		}
		normal := NormalizeLiterals(selected)
		for _, sameCase := range []bool{false, true} {
			for edits := 0; edits <= 2; edits++ {
				for _, boundary := range []bool{false, true} {
					if accepts(normal, sameCase, edits, boundary) != accepts(selected, sameCase, edits, boundary) {
						t.Fatalf("normalization changed matching: mask=%d case=%v edits=%d boundary=%v", mask, sameCase, edits, boundary)
					}
				}
			}
		}
		reversed := slices.Clone(selected)
		slices.Reverse(reversed)
		doubled := append(slices.Clone(selected), selected...)
		if !reflect.DeepEqual(normal, NormalizeLiterals(reversed)) || !reflect.DeepEqual(normal, NormalizeLiterals(doubled)) {
			t.Fatalf("normalization depends on order or repetition: mask=%d", mask)
		}
	}
}
