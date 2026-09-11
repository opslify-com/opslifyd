package memory

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// Chunking and BM25 scoring.
//
// Both are deliberately plain. The value of lexical retrieval here is that it is
// reproducible — a Change's citation list can be re-run a year later and return
// the same documents — and every piece of cleverness added to the scorer is a
// way for that to stop being true.

// chunk splits a document on its headings.
//
// Heading-aware because operator documents are structured: "## Rollback",
// "## Prerequisites". Carrying the heading path into the chunk and indexing it
// with the body is what lets a keyword search find the rollback section of a
// document titled "Deploying", which is most of what a semantic index would have
// bought.
func chunk(doc, content string) []Chunk {
	lines := strings.Split(content, "\n")
	var out []Chunk

	// headings[level] is the current heading at that depth, so a chunk under
	// "# Deploy" / "## Rollback" carries "Deploy > Rollback".
	var headings [7]string
	cur := []string{}
	start := 1

	flush := func(end int) {
		body := strings.TrimSpace(strings.Join(cur, "\n"))
		if body == "" {
			cur = nil
			return
		}
		h := headingPath(headings)
		c := Chunk{Doc: doc, Heading: h, StartLine: start, EndLine: end, Text: body}
		// The heading path is indexed with the body, not just displayed.
		c.terms, c.len = tokenize(h + "\n" + body)
		out = append(out, c)
		cur = nil
	}

	for i, line := range lines {
		lvl, text := headingOf(line)
		if lvl > 0 {
			flush(i) // the previous section ends where this heading begins
			for d := lvl; d < len(headings); d++ {
				headings[d] = ""
			}
			headings[lvl] = text
			start = i + 1
			cur = append(cur, line)
			continue
		}
		cur = append(cur, line)
	}
	flush(len(lines))

	// A document with no headings at all still has to be retrievable.
	if len(out) == 0 {
		body := strings.TrimSpace(content)
		if body == "" {
			return nil
		}
		c := Chunk{Doc: doc, StartLine: 1, EndLine: len(lines), Text: body}
		c.terms, c.len = tokenize(body)
		out = append(out, c)
	}
	return out
}

func headingOf(line string) (int, string) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "#") {
		return 0, ""
	}
	lvl := 0
	for lvl < len(t) && t[lvl] == '#' {
		lvl++
	}
	if lvl > 6 {
		return 0, ""
	}
	return lvl, strings.TrimSpace(t[lvl:])
}

func headingPath(h [7]string) string {
	var parts []string
	for i := 1; i < len(h); i++ {
		if h[i] != "" {
			parts = append(parts, h[i])
		}
	}
	return strings.Join(parts, " > ")
}

// tokenize lowercases, splits on non-alphanumerics, and drops stopwords. No
// stemming: "deploy" and "deployed" stay distinct, which costs some recall and
// buys the property that an operator can predict what a query will match.
func tokenize(s string) (map[string]int, int) {
	terms := map[string]int{}
	n := 0
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_'
	}) {
		f = strings.Trim(f, "-_")
		if len(f) < 2 || stopwords[f] {
			continue
		}
		terms[f]++
		n++
	}
	return terms, n
}

var stopwords = map[string]bool{
	"the": true, "and": true, "for": true, "are": true, "but": true, "not": true,
	"you": true, "all": true, "can": true, "has": true, "have": true, "was": true,
	"this": true, "that": true, "with": true, "from": true, "your": true, "our": true,
	"will": true, "when": true, "how": true, "why": true, "its": true, "it": true,
	"is": true, "of": true, "to": true, "in": true, "on": true, "as": true, "at": true,
	"by": true, "or": true, "an": true, "a": true, "we": true, "be": true, "if": true,
}

// index computes the BM25 inputs over the chunk set.
func (s *Store) index() {
	s.df = map[string]int{}
	total := 0
	for i := range s.chunks {
		total += s.chunks[i].len
		for term := range s.chunks[i].terms {
			s.df[term]++
		}
	}
	if len(s.chunks) > 0 {
		s.avgLen = float64(total) / float64(len(s.chunks))
	}
}

// BM25 parameters. The textbook defaults; there is no tuning corpus here, and
// inventing one would make the scores look authoritative without being so.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// Search returns the best k excerpts for a query.
//
// Deterministic in every respect, including ties: equal scores break on document
// path then start line, so the same corpus and query always produce the same
// citation list. A Change's provenance record depends on that.
func (s *Store) Search(query string, k int) []Excerpt {
	if k <= 0 {
		k = DefaultK
	}
	qterms, _ := tokenize(query)
	if len(qterms) == 0 || len(s.chunks) == 0 {
		return nil
	}
	n := float64(len(s.chunks))

	type scored struct {
		i     int
		score float64
	}
	var hits []scored
	for i := range s.chunks {
		c := &s.chunks[i]
		var score float64
		for term := range qterms {
			tf, ok := c.terms[term]
			if !ok {
				continue
			}
			df := float64(s.df[term])
			// The standard BM25 IDF, floored at zero: a term in nearly every chunk
			// otherwise scores negative and starts penalising the documents that
			// contain it, which reads as a bug to anyone reading the results.
			idf := math.Log(1 + (n-df+0.5)/(df+0.5))
			if idf < 0 {
				idf = 0
			}
			f := float64(tf)
			norm := f * (bm25K1 + 1) /
				(f + bm25K1*(1-bm25B+bm25B*float64(c.len)/max(s.avgLen, 1)))
			score += idf * norm
		}
		if score > 0 {
			hits = append(hits, scored{i, score})
		}
	}
	sort.Slice(hits, func(a, b int) bool {
		if hits[a].score != hits[b].score {
			return hits[a].score > hits[b].score
		}
		ca, cb := s.chunks[hits[a].i], s.chunks[hits[b].i]
		if ca.Doc != cb.Doc {
			return ca.Doc < cb.Doc
		}
		return ca.StartLine < cb.StartLine
	})
	if len(hits) > k {
		hits = hits[:k]
	}

	titles := map[string]string{}
	for _, d := range s.docs {
		titles[d.Rel] = d.Title
	}

	out := make([]Excerpt, 0, len(hits))
	for _, h := range hits {
		c := s.chunks[h.i]
		text := c.Text
		truncated := false
		if len(text) > DefaultExcerptCap {
			text = text[:DefaultExcerptCap]
			truncated = true
		}
		out = append(out, Excerpt{
			Doc: c.Doc, Title: titles[c.Doc], Heading: c.Heading,
			StartLine: c.StartLine, EndLine: c.EndLine,
			Text: text, Score: h.score, Truncated: truncated,
		})
	}
	return out
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
