package external

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/futureagi/agentcc-gateway/internal/guardrails"
)

type lakeraAdapter struct {
	apiKey     string
	endpoint   string
	categories []string
}

type lakeraMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type lakeraRequest struct {
	Messages  []lakeraMessage `json:"messages"`
	Breakdown bool            `json:"breakdown,omitempty"`
}

type lakeraDetectorResult struct {
	DetectorID   string   `json:"detector_id,omitempty"`
	DetectorType string   `json:"detector_type"`
	Detected     bool     `json:"detected"`
	Score        *float64 `json:"score,omitempty"`
}

type lakeraResponse struct {
	Flagged        bool                   `json:"flagged"`
	Breakdown      []lakeraDetectorResult `json:"breakdown,omitempty"`
	Categories     map[string]bool        `json:"categories,omitempty"`
	CategoryScores map[string]float64     `json:"category_scores,omitempty"`
}

func newLakeraAdapter(cfg map[string]interface{}) *lakeraAdapter {
	return &lakeraAdapter{
		apiKey:     getStringConfig(cfg, "api_key", ""),
		endpoint:   getStringConfig(cfg, "endpoint", "https://api.lakera.ai/v2/guard"),
		categories: getStringSliceConfig(cfg, "categories"),
	}
}

func (a *lakeraAdapter) buildRequest(ctx context.Context, text string) (*http.Request, error) {
	req := lakeraRequest{
		Messages: []lakeraMessage{
			{Role: "user", Content: text},
		},
		Breakdown: true,
	}
	return makeJSONRequest(ctx, a.endpoint, req, map[string]string{
		"Authorization": "Bearer " + a.apiKey,
	})
}

func (a *lakeraAdapter) parseResponse(body []byte) *guardrails.CheckResult {
	var resp lakeraResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return &guardrails.CheckResult{Pass: false, Score: 1.0, Message: fmt.Sprintf("failed to parse lakera response: %v", err)}
	}

	if !resp.Flagged {
		return &guardrails.CheckResult{Pass: true, Score: 0.0, Message: "content is safe"}
	}

	var triggered []string
	seen := make(map[string]bool)
	maxScore := 0.0

	addTriggered := func(cat string, score float64) {
		if !seen[cat] {
			seen[cat] = true
			triggered = append(triggered, cat)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	if len(a.categories) == 0 {
		// All categories.
		for _, b := range resp.Breakdown {
			if b.Detected {
				score := 0.0
				if b.Score != nil {
					score = *b.Score
				} else if s, ok := resp.CategoryScores[b.DetectorType]; ok {
					score = s
				}
				addTriggered(b.DetectorType, score)
			}
		}
		for cat, flagged := range resp.Categories {
			if flagged {
				addTriggered(cat, resp.CategoryScores[cat])
			}
		}
		// If flagged is true but breakdown/categories did not contain specific detector types
		if len(triggered) == 0 {
			addTriggered("content", 1.0)
		}
	} else {
		// Only check configured categories.
		for _, b := range resp.Breakdown {
			if b.Detected {
				for _, configuredCat := range a.categories {
					if matchCategory(configuredCat, b.DetectorType) {
						score := 0.0
						if b.Score != nil {
							score = *b.Score
						} else if s, ok := resp.CategoryScores[b.DetectorType]; ok {
							score = s
						} else if s, ok := resp.CategoryScores[configuredCat]; ok {
							score = s
						}
						addTriggered(b.DetectorType, score)
					}
				}
			}
		}
		for _, cat := range a.categories {
			if resp.Categories[cat] {
				addTriggered(cat, resp.CategoryScores[cat])
			}
		}
	}

	if len(triggered) == 0 {
		return &guardrails.CheckResult{Pass: true, Score: 0.0, Message: "flagged but no configured categories matched"}
	}

	if maxScore == 0.0 {
		maxScore = 1.0
	}

	details := map[string]interface{}{
		"categories": triggered,
	}
	if len(resp.CategoryScores) > 0 {
		details["category_scores"] = resp.CategoryScores
	}
	if len(resp.Breakdown) > 0 {
		details["breakdown"] = resp.Breakdown
	}

	return &guardrails.CheckResult{
		Pass:    false,
		Score:   maxScore,
		Message: fmt.Sprintf("lakera flagged: %s", strings.Join(triggered, ", ")),
		Details: details,
	}
}

func matchCategory(configuredCat, detectorType string) bool {
	if configuredCat == detectorType {
		return true
	}
	if strings.HasPrefix(detectorType, configuredCat+"/") {
		return true
	}
	if (configuredCat == "prompt_injection" || configuredCat == "prompt_attack") &&
		(detectorType == "prompt_injection" || detectorType == "prompt_attack") {
		return true
	}
	return false
}
