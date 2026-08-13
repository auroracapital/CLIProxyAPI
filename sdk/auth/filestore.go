package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// PluginAuthParser parses auth JSON owned by plugin providers.
type PluginAuthParser interface {
	ParseAuth(context.Context, pluginapi.AuthParseRequest) (*cliproxyauth.Auth, bool, error)
}

// PluginMultiAuthParser expands one auth JSON payload into multiple plugin auth records.
// Returning handled=true with an empty slice means the plugin intentionally suppresses built-in parsing.
type PluginMultiAuthParser interface {
	ParseAuths(context.Context, pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error)
}

type pluginAuthParserHolder struct {
	parser PluginAuthParser
}

var pluginAuthParserValue atomic.Value

// RegisterPluginAuthParser registers the current plugin auth parser.
func RegisterPluginAuthParser(parser PluginAuthParser) {
	pluginAuthParserValue.Store(pluginAuthParserHolder{parser: parser})
}

func currentPluginAuthParser() PluginAuthParser {
	value := pluginAuthParserValue.Load()
	if value == nil {
		return nil
	}
	holder, ok := value.(pluginAuthParserHolder)
	if !ok {
		return nil
	}
	return holder.parser
}

// FileTokenStore persists token records and auth metadata using the filesystem as backing storage.
type FileTokenStore struct {
	mu      sync.Mutex
	dirLock sync.RWMutex
	baseDir string
}

// NewFileTokenStore creates a token store that saves credentials to disk through the
// TokenStorage implementation embedded in the token record.
func NewFileTokenStore() *FileTokenStore {
	return &FileTokenStore{}
}

// SetBaseDir updates the default directory used for auth JSON persistence when no explicit path is provided.
func (s *FileTokenStore) SetBaseDir(dir string) {
	s.dirLock.Lock()
	s.baseDir = strings.TrimSpace(dir)
	s.dirLock.Unlock()
}

// Save persists token storage and metadata to the resolved auth file path.
func (s *FileTokenStore) Save(ctx context.Context, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth filestore: auth is nil")
	}
	if errWeight := cliproxyauth.ValidateAuthWeight(auth); errWeight != nil {
		return "", fmt.Errorf("auth filestore: %w", errWeight)
	}

	path, err := s.resolveAuthPath(auth)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("auth filestore: missing file path attribute for %s", auth.ID)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("auth filestore: create dir failed: %w", err)
	}

	if auth.Disabled {
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			return "", nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, errLock := lockReconcilePath(path)
	if errLock != nil {
		return "", errLock
	}
	defer unlock()
	targetPath := path
	stagedPath := ""
	if auth.Storage != nil {
		staged, errStage := os.CreateTemp(filepath.Dir(path), ".auth-save-")
		if errStage != nil {
			return "", fmt.Errorf("auth filestore: create save temp: %w", errStage)
		}
		stagedPath = staged.Name()
		if errClose := staged.Close(); errClose != nil {
			_ = os.Remove(stagedPath)
			return "", fmt.Errorf("auth filestore: close save temp: %w", errClose)
		}
		targetPath = stagedPath
		defer func() { _ = os.Remove(stagedPath) }()
	}

	// metadataSetter is a private interface for TokenStorage implementations that support metadata injection.
	type metadataSetter interface {
		SetMetadata(map[string]any)
	}

	switch {
	case auth.Storage != nil:
		if auth.Metadata == nil {
			auth.Metadata = make(map[string]any)
		}
		auth.Metadata["disabled"] = auth.Disabled
		if setter, ok := auth.Storage.(metadataSetter); ok {
			setter.SetMetadata(auth.Metadata)
		}
		if err = auth.Storage.SaveTokenToFile(targetPath); err != nil {
			return "", err
		}
		info, errStat := os.Lstat(targetPath)
		if errStat != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("auth filestore: saved credential is unsafe")
		}
		if errChmod := os.Chmod(targetPath, 0o600); errChmod != nil {
			return "", fmt.Errorf("auth filestore: secure saved credential: %w", errChmod)
		}
		file, errOpen := os.Open(targetPath)
		if errOpen != nil {
			return "", fmt.Errorf("auth filestore: open saved credential: %w", errOpen)
		}
		if errSync := file.Sync(); errSync != nil {
			_ = file.Close()
			return "", fmt.Errorf("auth filestore: sync saved credential: %w", errSync)
		}
		if errClose := file.Close(); errClose != nil {
			return "", fmt.Errorf("auth filestore: close saved credential: %w", errClose)
		}
		if errRename := os.Rename(targetPath, path); errRename != nil {
			return "", fmt.Errorf("auth filestore: replace saved credential: %w", errRename)
		}
	case auth.Metadata != nil:
		auth.Metadata["disabled"] = auth.Disabled
		raw, errMarshal := json.Marshal(auth.Metadata)
		if errMarshal != nil {
			return "", fmt.Errorf("auth filestore: marshal metadata failed: %w", errMarshal)
		}
		if existing, errRead := os.ReadFile(path); errRead == nil && jsonEqual(existing, raw) {
			break
		} else if errRead != nil && !os.IsNotExist(errRead) {
			return "", fmt.Errorf("auth filestore: read existing failed: %w", errRead)
		}
		temp, errTemp := os.CreateTemp(filepath.Dir(path), ".auth-save-")
		if errTemp != nil {
			return "", fmt.Errorf("auth filestore: create metadata temp: %w", errTemp)
		}
		tempPath := temp.Name()
		defer func() { _ = os.Remove(tempPath) }()
		if errChmod := temp.Chmod(0o600); errChmod != nil {
			_ = temp.Close()
			return "", fmt.Errorf("auth filestore: secure metadata temp: %w", errChmod)
		}
		if _, errWrite := temp.Write(raw); errWrite != nil {
			_ = temp.Close()
			return "", fmt.Errorf("auth filestore: write metadata temp: %w", errWrite)
		}
		if errSync := temp.Sync(); errSync != nil {
			_ = temp.Close()
			return "", fmt.Errorf("auth filestore: sync metadata temp: %w", errSync)
		}
		if errClose := temp.Close(); errClose != nil {
			return "", fmt.Errorf("auth filestore: close metadata temp: %w", errClose)
		}
		if errRename := os.Rename(tempPath, path); errRename != nil {
			return "", fmt.Errorf("auth filestore: replace metadata credential: %w", errRename)
		}
	default:
		return "", fmt.Errorf("auth filestore: nothing to persist for %s", auth.ID)
	}
	if errSyncDir := syncDirectory(filepath.Dir(path)); errSyncDir != nil {
		return "", errSyncDir
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes[cliproxyauth.AttributePath] = path
	auth.Attributes[cliproxyauth.AttributeSource] = path
	auth.Attributes[cliproxyauth.AttributeSourceBackend] = cliproxyauth.AuthSourceFile

	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = auth.ID
	}
	if persisted, errReadGeneration := os.ReadFile(path); errReadGeneration == nil {
		digest := sha256.Sum256(persisted)
		if auth.Attributes == nil {
			auth.Attributes = make(map[string]string)
		}
		auth.Attributes[cliproxyauth.AttributeSourceGeneration] = fmt.Sprintf("%x", digest[:])
	}

	return path, nil
}

func syncDirectory(path string) error {
	directory, errOpen := os.Open(path)
	if errOpen != nil {
		return fmt.Errorf("auth filestore: open credential directory: %w", errOpen)
	}
	if errSync := directory.Sync(); errSync != nil {
		_ = directory.Close()
		return fmt.Errorf("auth filestore: sync credential directory: %w", errSync)
	}
	if errClose := directory.Close(); errClose != nil {
		return fmt.Errorf("auth filestore: close credential directory: %w", errClose)
	}
	return nil
}

// LoadReconcile returns an auth rebuilt from the exact durable file generation.
// Runtime-only fields come from reference, while credential and admission fields
// always come from disk.
func (s *FileTokenStore) LoadReconcile(_ context.Context, reference *cliproxyauth.Auth) (*cliproxyauth.Auth, string, error) {
	if reference == nil {
		return nil, "", fmt.Errorf("auth filestore: reconcile reference is nil")
	}
	path, errPath := s.resolveAuthPath(reference)
	if errPath != nil || path == "" {
		return nil, "", fmt.Errorf("auth filestore: reconcile path unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, errLock := lockReconcilePath(path)
	if errLock != nil {
		return nil, "", errLock
	}
	defer unlock()
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return nil, "", fmt.Errorf("auth filestore: read reconcile credential: %w", errRead)
	}
	var metadata map[string]any
	if errJSON := json.Unmarshal(raw, &metadata); errJSON != nil || metadata == nil {
		return nil, "", fmt.Errorf("auth filestore: invalid reconcile credential")
	}
	provider, _ := metadata["type"].(string)
	provider = strings.TrimSpace(provider)
	if strings.EqualFold(provider, "gemini") {
		provider = "gemini-cli"
	}
	if !strings.EqualFold(provider, strings.TrimSpace(reference.Provider)) {
		return nil, "", fmt.Errorf("auth filestore: reconcile provider mismatch")
	}
	loaded := reference.Clone()
	loaded.Storage = nil
	loaded.Metadata = metadata
	loaded.Disabled, _ = metadata["disabled"].(bool)
	if loaded.Disabled {
		loaded.Status = cliproxyauth.StatusDisabled
	} else if loaded.Status == cliproxyauth.StatusDisabled {
		loaded.Status = cliproxyauth.StatusActive
	}
	loaded.ReconcileState = ""
	loaded.ReconcileReason = ""
	loaded.ReconcileNextAttempt = time.Time{}
	cliproxyauth.HydrateReconcileMetadata(loaded, metadata)
	digest := sha256.Sum256(raw)
	generation := fmt.Sprintf("%x", digest[:])
	if loaded.Attributes == nil {
		loaded.Attributes = make(map[string]string)
	}
	loaded.Attributes[cliproxyauth.AttributeSourceGeneration] = generation
	return loaded, generation, nil
}

// SaveReconcileCAS atomically changes lifecycle/admission metadata only when
// the on-disk credential is still the generation the caller loaded.
func (s *FileTokenStore) SaveReconcileCAS(_ context.Context, auth *cliproxyauth.Auth, expectedGeneration string) (string, string, error) {
	if auth == nil || auth.Metadata == nil {
		return "", "", fmt.Errorf("auth filestore: incomplete reconcile update")
	}
	path, errPath := s.resolveAuthPath(auth)
	if errPath != nil || path == "" {
		return "", "", fmt.Errorf("auth filestore: reconcile path unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, errLock := lockReconcilePath(path)
	if errLock != nil {
		return "", "", errLock
	}
	defer unlock()
	current, errRead := os.ReadFile(path)
	if errRead != nil {
		return "", "", fmt.Errorf("auth filestore: read reconcile generation: %w", errRead)
	}
	currentDigest := sha256.Sum256(current)
	if !strings.EqualFold(strings.TrimSpace(expectedGeneration), fmt.Sprintf("%x", currentDigest[:])) {
		return "", "", cliproxyauth.ErrReconcileGenerationMismatch
	}
	auth.Metadata["disabled"] = auth.Disabled
	raw, errJSON := json.Marshal(auth.Metadata)
	if errJSON != nil {
		return "", "", fmt.Errorf("auth filestore: marshal reconcile update: %w", errJSON)
	}
	raw = append(raw, '\n')
	temp, errTemp := os.CreateTemp(filepath.Dir(path), ".reconcile-cas-")
	if errTemp != nil {
		return "", "", fmt.Errorf("auth filestore: create reconcile temp: %w", errTemp)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if errChmod := temp.Chmod(0o600); errChmod != nil {
		_ = temp.Close()
		return "", "", fmt.Errorf("auth filestore: secure reconcile temp: %w", errChmod)
	}
	if _, errWrite := temp.Write(raw); errWrite != nil {
		_ = temp.Close()
		return "", "", fmt.Errorf("auth filestore: write reconcile temp: %w", errWrite)
	}
	if errSync := temp.Sync(); errSync != nil {
		_ = temp.Close()
		return "", "", fmt.Errorf("auth filestore: sync reconcile temp: %w", errSync)
	}
	if errClose := temp.Close(); errClose != nil {
		return "", "", fmt.Errorf("auth filestore: close reconcile temp: %w", errClose)
	}
	if errRename := os.Rename(tempPath, path); errRename != nil {
		return "", "", fmt.Errorf("auth filestore: replace reconcile credential: %w", errRename)
	}
	directory, errOpenDir := os.Open(filepath.Dir(path))
	if errOpenDir != nil {
		return "", "", fmt.Errorf("auth filestore: open reconcile directory: %w", errOpenDir)
	}
	if errSyncDir := directory.Sync(); errSyncDir != nil {
		_ = directory.Close()
		return "", "", fmt.Errorf("auth filestore: sync reconcile directory: %w", errSyncDir)
	}
	if errCloseDir := directory.Close(); errCloseDir != nil {
		return "", "", fmt.Errorf("auth filestore: close reconcile directory: %w", errCloseDir)
	}
	info, errStat := os.Lstat(path)
	if errStat != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return "", "", fmt.Errorf("auth filestore: reconcile credential permissions invalid")
	}
	newDigest := sha256.Sum256(raw)
	return path, fmt.Sprintf("%x", newDigest[:]), nil
}

// List enumerates all auth JSON files under the configured directory.
func (s *FileTokenStore) List(ctx context.Context) ([]*cliproxyauth.Auth, error) {
	dir := s.baseDirSnapshot()
	if dir == "" {
		return nil, fmt.Errorf("auth filestore: directory not configured")
	}
	entries := make([]*cliproxyauth.Auth, 0)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		auths, errReadAuths := s.readAuthFiles(path, dir)
		if errReadAuths != nil {
			return nil
		}
		if len(auths) > 0 {
			entries = append(entries, auths...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// Delete removes the auth file.
func (s *FileTokenStore) Delete(ctx context.Context, id string) error {
	_ = ctx
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("auth filestore: id is empty")
	}
	path, err := s.resolveDeletePath(id)
	if err != nil {
		return err
	}
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o700); errMkdir != nil {
		return fmt.Errorf("auth filestore: create delete dir: %w", errMkdir)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, errLock := lockReconcilePath(path)
	if errLock != nil {
		return errLock
	}
	defer unlock()
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("auth filestore: delete failed: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func (s *FileTokenStore) resolveDeletePath(id string) (string, error) {
	if strings.ContainsRune(id, os.PathSeparator) || filepath.IsAbs(id) {
		return id, nil
	}
	dir := s.baseDirSnapshot()
	if dir == "" {
		return "", fmt.Errorf("auth filestore: directory not configured")
	}
	return filepath.Join(dir, id), nil
}

func (s *FileTokenStore) readAuthFiles(path, baseDir string) ([]*cliproxyauth.Auth, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	metadata := make(map[string]any)
	if err = json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal auth json: %w", err)
	}
	if errWeight := cliproxyauth.ValidateAuthWeight(&cliproxyauth.Auth{Metadata: metadata}); errWeight != nil {
		return nil, errWeight
	}
	provider, _ := metadata["type"].(string)
	provider = strings.TrimSpace(provider)
	if strings.EqualFold(provider, "gemini") {
		return nil, nil
	}
	info, errStat := os.Stat(path)
	if errStat != nil {
		return nil, fmt.Errorf("stat file: %w", errStat)
	}
	if parser := currentPluginAuthParser(); parser != nil {
		auths, handled, errParse := parsePluginAuthFile(parser, pluginapi.AuthParseRequest{
			Provider: provider,
			Path:     path,
			FileName: s.idFor(path, baseDir),
			RawJSON:  data,
		})
		if errParse == nil && handled {
			auths = compactPluginAuths(auths)
			if len(auths) == 0 {
				return nil, nil
			}
			disabled, _ := metadata["disabled"].(bool)
			for index, auth := range auths {
				if auth == nil {
					continue
				}
				if len(auths) > 1 {
					cliproxyauth.MarkPluginVirtualAuth(auth, path, index)
				}
				auth.CreatedAt = info.ModTime()
				auth.UpdatedAt = info.ModTime()
				if auth.Attributes == nil {
					auth.Attributes = make(map[string]string)
				}
				auth.Attributes[cliproxyauth.AttributePath] = path
				auth.Attributes[cliproxyauth.AttributeSource] = path
				auth.Attributes[cliproxyauth.AttributeSourceBackend] = cliproxyauth.AuthSourceFile
				if disabled {
					auth.Disabled = true
					auth.Status = cliproxyauth.StatusDisabled
					if auth.Metadata == nil {
						auth.Metadata = make(map[string]any)
					}
					auth.Metadata["disabled"] = true
				}
				if errWeight := cliproxyauth.ApplyAuthWeightMetadata(auth, metadata); errWeight != nil {
					return nil, errWeight
				}
				cliproxyauth.ApplyCustomHeadersFromMetadata(auth)
				cliproxyauth.HydrateReconcileMetadata(auth, metadata)
			}
			return auths, nil
		}
	}
	if provider == "" {
		provider = "unknown"
	}
	if provider == "antigravity" {
		projectID := ""
		if pid, ok := metadata["project_id"].(string); ok {
			projectID = strings.TrimSpace(pid)
		}
		if projectID == "" {
			accessToken := extractAccessToken(metadata)
			if accessToken != "" {
				fetchedProjectID, errFetch := FetchAntigravityProjectID(context.Background(), accessToken, http.DefaultClient)
				if errFetch == nil && strings.TrimSpace(fetchedProjectID) != "" {
					metadata["project_id"] = strings.TrimSpace(fetchedProjectID)
					if raw, errMarshal := json.Marshal(metadata); errMarshal == nil {
						if file, errOpen := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600); errOpen == nil {
							_, _ = file.Write(raw)
							_ = file.Close()
						}
					}
				}
			}
		}
	}
	info, errStat = os.Stat(path)
	if errStat != nil {
		return nil, fmt.Errorf("stat file: %w", errStat)
	}
	id := s.idFor(path, baseDir)
	disabled, _ := metadata["disabled"].(bool)
	status := cliproxyauth.StatusActive
	if disabled {
		status = cliproxyauth.StatusDisabled
	}
	auth := &cliproxyauth.Auth{
		ID:       id,
		Provider: provider,
		FileName: id,
		Label:    s.labelFor(metadata),
		Status:   status,
		Disabled: disabled,
		Attributes: map[string]string{
			cliproxyauth.AttributePath:             path,
			cliproxyauth.AttributeSource:           path,
			cliproxyauth.AttributeSourceBackend:    cliproxyauth.AuthSourceFile,
			cliproxyauth.AttributeSourceGeneration: fmt.Sprintf("%x", sha256.Sum256(data)),
		},
		Metadata:         metadata,
		CreatedAt:        info.ModTime(),
		UpdatedAt:        info.ModTime(),
		LastRefreshedAt:  time.Time{},
		NextRefreshAfter: time.Time{},
	}
	if email, ok := metadata["email"].(string); ok && email != "" {
		auth.Attributes["email"] = email
	}
	cliproxyauth.ApplyCustomHeadersFromMetadata(auth)
	cliproxyauth.HydrateReconcileMetadata(auth, metadata)
	return []*cliproxyauth.Auth{auth}, nil
}

func (s *FileTokenStore) readAuthFile(path, baseDir string) (*cliproxyauth.Auth, error) {
	auths, errReadAuths := s.readAuthFiles(path, baseDir)
	if errReadAuths != nil || len(auths) == 0 {
		return nil, errReadAuths
	}
	return auths[0], nil
}

func parsePluginAuthFile(parser PluginAuthParser, req pluginapi.AuthParseRequest) ([]*cliproxyauth.Auth, bool, error) {
	if parser == nil {
		return nil, false, nil
	}
	if multiParser, ok := parser.(PluginMultiAuthParser); ok {
		return multiParser.ParseAuths(context.Background(), req)
	}
	auth, handled, errParse := parser.ParseAuth(context.Background(), req)
	if errParse != nil || !handled || auth == nil {
		return nil, handled, errParse
	}
	return []*cliproxyauth.Auth{auth}, true, nil
}

func compactPluginAuths(auths []*cliproxyauth.Auth) []*cliproxyauth.Auth {
	if len(auths) == 0 {
		return nil
	}
	out := auths[:0]
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if errWeight := cliproxyauth.ValidateAuthWeight(auth); errWeight != nil {
			continue
		}
		out = append(out, auth)
	}
	return out
}

func (s *FileTokenStore) idFor(path, baseDir string) string {
	id := path
	if baseDir != "" {
		if rel, errRel := filepath.Rel(baseDir, path); errRel == nil && rel != "" {
			id = rel
		}
	}
	// On Windows, normalize ID casing to avoid duplicate auth entries caused by case-insensitive paths.
	if runtime.GOOS == "windows" {
		id = strings.ToLower(id)
	}
	return id
}

func (s *FileTokenStore) resolveAuthPath(auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth filestore: auth is nil")
	}
	if auth.Attributes != nil {
		if p := strings.TrimSpace(auth.Attributes["path"]); p != "" {
			return p, nil
		}
	}
	if fileName := strings.TrimSpace(auth.FileName); fileName != "" {
		if filepath.IsAbs(fileName) {
			return fileName, nil
		}
		if dir := s.baseDirSnapshot(); dir != "" {
			return filepath.Join(dir, fileName), nil
		}
		return fileName, nil
	}
	if auth.ID == "" {
		return "", fmt.Errorf("auth filestore: missing id")
	}
	if filepath.IsAbs(auth.ID) {
		return auth.ID, nil
	}
	dir := s.baseDirSnapshot()
	if dir == "" {
		return "", fmt.Errorf("auth filestore: directory not configured")
	}
	return filepath.Join(dir, auth.ID), nil
}

func (s *FileTokenStore) labelFor(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	if v, ok := metadata["label"].(string); ok && v != "" {
		return v
	}
	if v, ok := metadata["email"].(string); ok && v != "" {
		return v
	}
	if project, ok := metadata["project_id"].(string); ok && project != "" {
		return project
	}
	return ""
}

func (s *FileTokenStore) baseDirSnapshot() string {
	s.dirLock.RLock()
	defer s.dirLock.RUnlock()
	return s.baseDir
}

func extractAccessToken(metadata map[string]any) string {
	if at, ok := metadata["access_token"].(string); ok {
		if v := strings.TrimSpace(at); v != "" {
			return v
		}
	}
	if tokenMap, ok := metadata["token"].(map[string]any); ok {
		if at, ok := tokenMap["access_token"].(string); ok {
			if v := strings.TrimSpace(at); v != "" {
				return v
			}
		}
	}
	return ""
}

// jsonEqual compares two JSON blobs by parsing them into Go objects and deep comparing.
func jsonEqual(a, b []byte) bool {
	var objA any
	var objB any
	if err := json.Unmarshal(a, &objA); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &objB); err != nil {
		return false
	}
	return deepEqualJSON(objA, objB)
}

func deepEqualJSON(a, b any) bool {
	switch valA := a.(type) {
	case map[string]any:
		valB, ok := b.(map[string]any)
		if !ok || len(valA) != len(valB) {
			return false
		}
		for key, subA := range valA {
			subB, ok1 := valB[key]
			if !ok1 || !deepEqualJSON(subA, subB) {
				return false
			}
		}
		return true
	case []any:
		sliceB, ok := b.([]any)
		if !ok || len(valA) != len(sliceB) {
			return false
		}
		for i := range valA {
			if !deepEqualJSON(valA[i], sliceB[i]) {
				return false
			}
		}
		return true
	case float64:
		valB, ok := b.(float64)
		if !ok {
			return false
		}
		return valA == valB
	case string:
		valB, ok := b.(string)
		if !ok {
			return false
		}
		return valA == valB
	case bool:
		valB, ok := b.(bool)
		if !ok {
			return false
		}
		return valA == valB
	case nil:
		return b == nil
	default:
		return false
	}
}
