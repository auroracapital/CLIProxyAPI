package handlers

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const (
	smartRouteScoreVersion = "v2"
	defaultAutoFallbacks   = 3
	maxAutoFallbacks       = 5
)

const (
	smartTaskCode       = "code"
	smartTaskReasoning  = "reasoning"
	smartTaskResearch   = "research"
	smartTaskAgent      = "agent"
	smartTaskMultimodal = "multimodal"
	smartTaskWriting    = "writing"
	smartTaskGeneral    = "general"
)

type smartRouteRequirements struct {
	TaskClass        string
	NeedsTools       bool
	NeedsImageInput  bool
	NeedsAudioInput  bool
	NeedsVideoInput  bool
	NeedsImageOutput bool
	NeedsJSONSchema  bool
	EstimatedInput   int
	RequestedOutput  int
	ClassifierReason string
}

type smartRouteDecision struct {
	TaskClass    string
	Models       []string
	Reason       string
	ScoreVersion string
	Mode         string
	Duration     time.Duration
	Providers    map[string][]string
}

type smartRoutePayload struct {
	Messages            []smartRouteMessage `json:"messages"`
	Input               json.RawMessage     `json:"input"`
	Prompt              json.RawMessage     `json:"prompt"`
	Tools               json.RawMessage     `json:"tools"`
	ToolChoice          json.RawMessage     `json:"tool_choice"`
	ResponseFormat      json.RawMessage     `json:"response_format"`
	MaxTokens           int                 `json:"max_tokens"`
	MaxOutputTokens     int                 `json:"max_output_tokens"`
	MaxCompletionTokens int                 `json:"max_completion_tokens"`
}

type smartRouteMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

var smartTaskKeywords = map[string][]string{
	smartTaskCode: {
		"bug", "debug", "code", "compile", "compiler", "function", "class", "repository", "refactor", "test", "typescript", "javascript", "python", "golang", "rust", "sql", "pull request", "stack trace",
	},
	smartTaskReasoning: {
		"prove", "proof", "theorem", "calculate", "equation", "math", "logic", "reason step", "optimization", "probability", "algorithm complexity",
	},
	smartTaskResearch: {
		"research", "sources", "citations", "compare evidence", "literature", "market analysis", "investigate", "report", "fact check",
	},
	smartTaskAgent: {
		"use tools", "tool call", "execute", "deploy", "browse", "search the web", "multi-step", "plan and implement", "operate", "automation",
	},
	smartTaskWriting: {
		"rewrite", "translate", "draft", "copyedit", "summarize", "summary", "email", "blog", "tone", "grammar",
	},
}

func isAutoModel(model string) bool {
	return model == "auto"
}

func autoRoutingMode(cfg internalconfig.AutoRoutingConfig) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" && cfg.Enabled {
		return "active"
	}
	switch mode {
	case "active", "shadow":
		return mode
	default:
		return "off"
	}
}

func (h *BaseAPIHandler) smartRoute(model string, rawJSON []byte) (smartRouteDecision, bool) {
	started := time.Now()
	decision := smartRouteDecision{ScoreVersion: smartRouteScoreVersion}
	if h == nil || !isAutoModel(model) {
		return decision, false
	}
	autoCfg := h.autoRoutingConfig()
	decision.Mode = autoRoutingMode(autoCfg)
	if decision.Mode == "off" {
		return decision, false
	}
	requirements := classifySmartRoute(rawJSON)
	configured := autoCfg.TaskModels[requirements.TaskClass]
	hasConfiguredTaskSlate := len(configured) > 0
	if len(configured) == 0 {
		configured = autoCfg.DefaultModels
	}
	limit := autoCfg.MaxFallbacks
	if limit < 1 {
		limit = defaultAutoFallbacks
	}
	if limit > maxAutoFallbacks {
		limit = maxAutoFallbacks
	}
	models, providers := eligibleSmartModels(configured, requirements, autoCfg.Policy, limit)
	if len(models) == 0 && !hasConfiguredTaskSlate && len(configured) == 0 {
		models = rankAvailableSmartModels(requirements, autoCfg.Policy, limit)
		providers = eligibleProvidersForModels(models, requirements, autoCfg.Policy)
	}
	if len(models) == 0 {
		decision.TaskClass = requirements.TaskClass
		decision.Reason = "no_compatible_model"
		decision.Duration = time.Since(started)
		return decision, true
	}
	decision.TaskClass = requirements.TaskClass
	decision.Models = models
	decision.Providers = providers
	decision.Reason = requirements.ClassifierReason
	decision.Duration = time.Since(started)
	return decision, true
}

func emitSmartRouteDecision(ctx context.Context, decision smartRouteDecision, observer coreexecutor.RoutingObserver) {
	selected := ""
	if len(decision.Models) > 0 {
		selected = decision.Models[0]
	}
	emitRoutingEvent(observer, coreexecutor.RoutingEvent{
		Stage:          "model_decision",
		Mode:           decision.Mode,
		TaskClass:      decision.TaskClass,
		ScoreVersion:   decision.ScoreVersion,
		Model:          selected,
		Reason:         decision.Reason,
		Outcome:        map[bool]string{true: "selected", false: "unavailable"}[selected != ""],
		CandidateCount: len(decision.Models),
		Duration:       decision.Duration,
		RequestBucket:  coreexecutor.RoutingRequestBucket(logging.GetRequestID(ctx)),
	})
}

func classifySmartRoute(rawJSON []byte) smartRouteRequirements {
	requirements := smartRouteRequirements{TaskClass: smartTaskGeneral, ClassifierReason: "general_default"}
	var payload smartRoutePayload
	if len(rawJSON) == 0 || json.Unmarshal(rawJSON, &payload) != nil {
		return requirements
	}
	requirements.NeedsTools = jsonCollectionPresent(payload.Tools) || jsonValuePresent(payload.ToolChoice)
	requirements.NeedsJSONSchema = bytesContainFold(payload.ResponseFormat, "json_schema") ||
		jsonPathContains(rawJSON, "text.format.type", "json_schema") ||
		gjson.GetBytes(rawJSON, "generation_config.response_schema").Exists() ||
		gjson.GetBytes(rawJSON, "generationConfig.responseSchema").Exists() ||
		gjson.GetBytes(rawJSON, "output_config.format.schema").Exists()
	requirements.RequestedOutput = payload.MaxOutputTokens
	if requirements.RequestedOutput <= 0 {
		requirements.RequestedOutput = payload.MaxCompletionTokens
	}
	if requirements.RequestedOutput <= 0 {
		requirements.RequestedOutput = payload.MaxTokens
	}
	for _, path := range []string{"generation_config.max_output_tokens", "generationConfig.maxOutputTokens"} {
		if value := int(gjson.GetBytes(rawJSON, path).Int()); value > requirements.RequestedOutput {
			requirements.RequestedOutput = value
		}
	}
	features := boundedPayloadFeatures(payload)
	// Use the complete serialized request for the conservative context estimate.
	// The bounded text feature string is only for task classification; using it
	// here would undercount long prompts, tool schemas, and encoded modalities.
	requirements.EstimatedInput = len(rawJSON) / 4
	modality := detectPayloadModalities(rawJSON)
	requirements.NeedsImageInput = modality.imageInput
	requirements.NeedsAudioInput = modality.audioInput
	requirements.NeedsVideoInput = modality.videoInput
	requirements.NeedsImageOutput = modality.imageOutput
	if requirements.NeedsImageInput || requirements.NeedsAudioInput || requirements.NeedsVideoInput || requirements.NeedsImageOutput {
		requirements.TaskClass = smartTaskMultimodal
		requirements.ClassifierReason = "hard_multimodal"
		return requirements
	}
	if requirements.NeedsTools {
		requirements.TaskClass = smartTaskAgent
		requirements.ClassifierReason = "hard_tools"
		return requirements
	}
	scores := make(map[string]int, len(smartTaskKeywords))
	lower := strings.ToLower(features)
	for task, keywords := range smartTaskKeywords {
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				scores[task]++
			}
		}
	}
	bestTask := smartTaskGeneral
	bestScore := 0
	for _, task := range []string{smartTaskCode, smartTaskReasoning, smartTaskResearch, smartTaskAgent, smartTaskWriting} {
		if scores[task] > bestScore {
			bestTask = task
			bestScore = scores[task]
		}
	}
	if bestScore > 0 {
		requirements.TaskClass = bestTask
		requirements.ClassifierReason = "keyword_" + bestTask
	}
	return requirements
}

type smartModalities struct {
	imageInput  bool
	audioInput  bool
	videoInput  bool
	imageOutput bool
}

func detectPayloadModalities(raw []byte) smartModalities {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return smartModalities{}
	}
	var result smartModalities
	inspectPayloadModalities(value, "", &result, 0)
	return result
}

func inspectPayloadModalities(value any, key string, result *smartModalities, depth int) {
	if result == nil || depth > 16 {
		return
	}
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			inspectPayloadModalities(item, key, result, depth+1)
		}
	case map[string]any:
		for itemKey, item := range typed {
			inspectPayloadModalities(item, strings.ToLower(strings.TrimSpace(itemKey)), result, depth+1)
		}
	case string:
		valueLower := strings.ToLower(strings.TrimSpace(typed))
		switch key {
		case "type":
			result.imageInput = result.imageInput || strings.HasPrefix(valueLower, "image") || valueLower == "input_image"
			result.audioInput = result.audioInput || strings.HasPrefix(valueLower, "audio") || valueLower == "input_audio"
			result.videoInput = result.videoInput || strings.HasPrefix(valueLower, "video") || valueLower == "input_video"
		case "modalities":
			result.imageOutput = result.imageOutput || valueLower == "image"
		}
	}
}

func boundedPayloadFeatures(payload smartRoutePayload) string {
	const maxFeatureBytes = 32768
	parts := make([]string, 0, len(payload.Messages)+2)
	for _, message := range payload.Messages {
		appendTextJSON(&parts, message.Content)
	}
	appendTextJSON(&parts, payload.Input)
	appendTextJSON(&parts, payload.Prompt)
	joined := strings.Join(parts, " ")
	if len(joined) > maxFeatureBytes {
		joined = joined[len(joined)-maxFeatureBytes:]
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, joined)
}

func appendTextJSON(parts *[]string, raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return
	}
	collectText(parts, value, 0)
}

func collectText(parts *[]string, value any, depth int) {
	if depth > 8 {
		return
	}
	switch typed := value.(type) {
	case string:
		*parts = append(*parts, typed)
	case []any:
		for _, item := range typed {
			collectText(parts, item, depth+1)
		}
	case map[string]any:
		for key, item := range typed {
			if key == "text" || key == "content" || key == "input_text" || key == "prompt" {
				collectText(parts, item, depth+1)
			}
		}
	}
}

func jsonCollectionPresent(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null" && trimmed != "[]" && trimmed != "{}"
}

func jsonValuePresent(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

func bytesContainFold(raw json.RawMessage, fragment string) bool {
	return strings.Contains(strings.ToLower(string(raw)), strings.ToLower(fragment))
}

func jsonPathContains(raw []byte, path, expected string) bool {
	return strings.EqualFold(strings.TrimSpace(gjson.GetBytes(raw, path).String()), expected)
}

func eligibleSmartModels(configured []string, requirements smartRouteRequirements, policy internalconfig.AutoRoutingPolicyConfig, limit int) ([]string, map[string][]string) {
	registryRef := registry.GetGlobalRegistry()
	seen := make(map[string]struct{}, len(configured))
	out := make([]string, 0, len(configured))
	providersByModel := make(map[string][]string, len(configured))
	for _, candidate := range configured {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || isAutoModel(candidate) {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		providers := eligibleSmartProviders(registryRef, candidate, requirements, policy)
		if len(providers) == 0 {
			continue
		}
		out = append(out, candidate)
		providersByModel[candidate] = providers
	}
	if len(out) == 0 {
		return nil, nil
	}
	applySmartModelPolicy(out, policy)
	if len(out) > limit {
		for _, model := range out[limit:] {
			delete(providersByModel, model)
		}
		out = out[:limit]
	}
	return out, providersByModel
}

func eligibleProvidersForModels(models []string, requirements smartRouteRequirements, policy internalconfig.AutoRoutingPolicyConfig) map[string][]string {
	registryRef := registry.GetGlobalRegistry()
	out := make(map[string][]string, len(models))
	for _, model := range models {
		if providers := eligibleSmartProviders(registryRef, model, requirements, policy); len(providers) > 0 {
			out[model] = providers
		}
	}
	return out
}

func eligibleSmartProviders(registryRef *registry.ModelRegistry, model string, requirements smartRouteRequirements, policy internalconfig.AutoRoutingPolicyConfig) []string {
	if registryRef == nil {
		return nil
	}
	providers := registryRef.GetModelProviders(model)
	out := make([]string, 0, len(providers))
	for _, provider := range providers {
		if !providerHasAvailableModel(registryRef, provider, model) {
			continue
		}
		info := registryRef.GetModelInfo(model, provider)
		if info != nil && smartModelSatisfies(info, requirements) {
			out = append(out, provider)
		}
	}
	applySmartProviderPolicy(out, policy)
	return out
}

func providerHasAvailableModel(registryRef *registry.ModelRegistry, provider, model string) bool {
	for _, info := range registryRef.GetAvailableModelsByProvider(provider) {
		if info != nil && info.ID == model {
			return true
		}
	}
	return false
}

func rankAvailableSmartModels(requirements smartRouteRequirements, policy internalconfig.AutoRoutingPolicyConfig, limit int) []string {
	infos := registry.GetGlobalRegistry().GetAvailableModelInfos()
	type scored struct {
		id    string
		score int
	}
	candidates := make([]scored, 0, len(infos))
	for _, info := range infos {
		if info == nil || isSpecializedGenerationModel(info.ID) || len(eligibleSmartProviders(registry.GetGlobalRegistry(), info.ID, requirements, policy)) == 0 {
			continue
		}
		candidates = append(candidates, scored{id: info.ID, score: smartModelTaskScore(info, requirements.TaskClass)})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		preference := smartModelPreference(policy)
		if len(preference) > 0 {
			iRank, iPreferred := smartPreferenceRank(preference, candidates[i].id)
			jRank, jPreferred := smartPreferenceRank(preference, candidates[j].id)
			if iPreferred != jPreferred {
				return iPreferred
			}
			if iPreferred && iRank != jRank {
				return iRank < jRank
			}
		}
		if candidates[i].score == candidates[j].score {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].score > candidates[j].score
	})
	out := make([]string, 0, limit)
	for _, candidate := range candidates {
		out = append(out, candidate.id)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func applySmartModelPolicy(models []string, policy internalconfig.AutoRoutingPolicyConfig) {
	preference := smartModelPreference(policy)
	if len(preference) == 0 {
		return
	}
	sort.SliceStable(models, func(i, j int) bool {
		iRank, iPreferred := smartPreferenceRank(preference, models[i])
		jRank, jPreferred := smartPreferenceRank(preference, models[j])
		if iPreferred != jPreferred {
			return iPreferred
		}
		return iPreferred && iRank < jRank
	})
}

func smartModelPreference(policy internalconfig.AutoRoutingPolicyConfig) []string {
	switch strings.ToLower(strings.TrimSpace(policy.Objective)) {
	case "quality":
		return policy.QualityModels
	case "cost":
		return policy.CostModels
	case "latency":
		return policy.LatencyModels
	default:
		return nil
	}
}

func applySmartProviderPolicy(providers []string, policy internalconfig.AutoRoutingPolicyConfig) {
	if !strings.EqualFold(strings.TrimSpace(policy.ProviderStrategy), "priority") || len(policy.ProviderPriority) == 0 {
		return
	}
	sort.SliceStable(providers, func(i, j int) bool {
		iRank, iPreferred := smartPreferenceRank(policy.ProviderPriority, providers[i])
		jRank, jPreferred := smartPreferenceRank(policy.ProviderPriority, providers[j])
		if iPreferred != jPreferred {
			return iPreferred
		}
		return iPreferred && iRank < jRank
	})
}

func smartPreferenceRank(preference []string, candidate string) (int, bool) {
	for index, preferred := range preference {
		if strings.EqualFold(strings.TrimSpace(preferred), strings.TrimSpace(candidate)) {
			return index, true
		}
	}
	return 0, false
}

func smartModelSatisfies(info *registry.ModelInfo, requirements smartRouteRequirements) bool {
	if info == nil {
		return false
	}
	contextLimit := info.MaxContextLength
	if contextLimit <= 0 {
		contextLimit = info.ContextLength
	}
	if contextLimit <= 0 {
		contextLimit = info.InputTokenLimit
	}
	if contextLimit > 0 && (requirements.EstimatedInput > contextLimit ||
		(requirements.RequestedOutput > 0 && requirements.EstimatedInput+requirements.RequestedOutput > contextLimit)) {
		return false
	}
	outputLimit := info.MaxCompletionTokens
	if outputLimit <= 0 {
		outputLimit = info.OutputTokenLimit
	}
	if outputLimit > 0 && requirements.RequestedOutput > outputLimit {
		return false
	}
	if requirements.NeedsImageInput && !containsFold(info.SupportedInputModalities, "image") {
		return false
	}
	if requirements.NeedsAudioInput && !containsFold(info.SupportedInputModalities, "audio") {
		return false
	}
	if requirements.NeedsVideoInput && !containsFold(info.SupportedInputModalities, "video") {
		return false
	}
	if requirements.NeedsImageOutput && !containsFold(info.SupportedOutputModalities, "image") {
		return false
	}
	if requirements.NeedsTools && !containsAnyFold(info.SupportedParameters, "tools", "tool_choice", "function_call") {
		return false
	}
	if requirements.NeedsJSONSchema && !containsAnyFold(info.SupportedParameters, "response_format", "json_schema", "structured_outputs", "response_schema") {
		return false
	}
	return true
}

func smartModelTaskScore(info *registry.ModelInfo, task string) int {
	id := strings.ToLower(info.ID)
	score := 0
	switch task {
	case smartTaskCode:
		if strings.Contains(id, "codex") || strings.Contains(id, "coding") || strings.Contains(id, "composer") || strings.Contains(id, "sol") {
			score += 30
		}
	case smartTaskReasoning:
		if strings.Contains(id, "opus") || strings.Contains(id, "reasoning") || strings.Contains(id, "pro") || strings.Contains(id, "sol") {
			score += 30
		}
	case smartTaskResearch, smartTaskAgent:
		if info.SupportsWebSearch || containsAnyFold(info.SupportedParameters, "tools", "tool_choice") {
			score += 25
		}
	case smartTaskWriting:
		if strings.Contains(id, "sonnet") || strings.Contains(id, "terra") || strings.Contains(id, "flash") {
			score += 20
		}
	case smartTaskMultimodal:
		score += 30
	}
	if info.Thinking != nil {
		score += 5
	}
	if info.MaxContextLength >= 1_000_000 || info.ContextLength >= 1_000_000 || info.InputTokenLimit >= 1_000_000 {
		score += 3
	}
	return score
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func containsAnyFold(values []string, expected ...string) bool {
	for _, candidate := range expected {
		if containsFold(values, candidate) {
			return true
		}
	}
	return false
}

func isSpecializedGenerationModel(model string) bool {
	lower := strings.ToLower(model)
	return strings.Contains(lower, "image") || strings.Contains(lower, "video") || strings.Contains(lower, "tts") || strings.Contains(lower, "embedding")
}
