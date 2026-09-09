package agentcontext

import "unicode/utf8"

// EstimateTokens approximates the token cost of a string.
//
// HONEST SCOPE: this is a heuristic, not a tokenizer. The daemon deliberately
// does not vendor a model-specific BPE table — the assembled context is sent to
// whichever agent the operator configured (Claude, a local Qwen, Codex), each
// with a different vocabulary, so any single "exact" count would be exact for at
// most one of them and quietly wrong for the rest.
//
// The heuristic: one token per 4 bytes of text, plus one per whitespace-delimited
// word, averaged. On English prose and markdown this lands within roughly ±20%
// of a BPE count, which is the documented tolerance. It is used for BUDGET
// WARNINGS only. Nothing is ever truncated on the strength of it — see Assemble,
// which reports an overrun and leaves the content whole, because a silent cut
// through an instruction file can inverse its meaning.
//
// It is exactly deterministic with respect to its own definition, which is what
// the assembly hash and the layer accounting actually require.
func EstimateTokens(s string) int {
	if s == "" {
		return 0
	}
	byteEstimate := (utf8.RuneCountInString(s) + 3) / 4

	words := 0
	inWord := false
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r':
			inWord = false
		default:
			if !inWord {
				words++
				inWord = true
			}
		}
	}
	est := (byteEstimate + words) / 2
	if est < 1 {
		est = 1
	}
	return est
}

// TokenTolerance documents the accuracy claim above, for the UI and for tests
// that assert the estimate is not wildly off a real count.
const TokenTolerance = 0.20
