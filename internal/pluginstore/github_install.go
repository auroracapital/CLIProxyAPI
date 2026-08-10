package pluginstore

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	GitHubSourceID   = "github-release"
	GitHubSourceName = "GitHub Release"
)

// GitHubInstallRequest describes a direct install from a standard GitHub
// Release repository without requiring a plugin store registry entry.
type GitHubInstallRequest struct {
	Repository string
	Version    string
	ID         string
	Options    InstallOptions
}

// InstallGitHubRepository installs the latest or requested release for a
// GitHub repository and returns a pinned manifest suitable for config storage.
func (c Client) InstallGitHubRepository(ctx context.Context, request GitHubInstallRequest) (InstallResult, Manifest, error) {
	repository, owner, errRepository := normalizeGitHubRepository(request.Repository)
	if errRepository != nil {
		return InstallResult{}, Manifest{}, errRepository
	}
	options := normalizeInstallOptions(request.Options)

	pluginForRelease := Plugin{Repository: repository}
	release, errRelease := c.fetchRequestedRelease(ctx, pluginForRelease, request.Version)
	if errRelease != nil {
		return InstallResult{}, Manifest{}, errRelease
	}
	version, errVersion := ReleaseVersion(release)
	if errVersion != nil {
		return InstallResult{}, Manifest{}, errVersion
	}
	if requestedVersion := normalizeVersion(request.Version); requestedVersion != "" && requestedVersion != version {
		return InstallResult{}, Manifest{}, fmt.Errorf("release tag %q resolved version %q, want %q", release.TagName, version, requestedVersion)
	}
	id, errID := releasePluginID(release, request.ID, version, options.GOOS, options.GOARCH)
	if errID != nil {
		return InstallResult{}, Manifest{}, errID
	}

	plugin := Plugin{
		ID:          id,
		Name:        id,
		Description: "Installed directly from GitHub Releases.",
		Author:      owner,
		Version:     version,
		Repository:  repository,
		Install:     InstallPlan{Type: InstallTypeGitHubRelease},
	}
	manifest, errManifest := ManifestFromRelease(Source{
		ID:   GitHubSourceID,
		Name: GitHubSourceName,
		URL:  repository,
	}, plugin, release)
	if errManifest != nil {
		return InstallResult{}, Manifest{}, fmt.Errorf("create GitHub release manifest: %w", errManifest)
	}
	if errValidate := manifest.Validate(); errValidate != nil {
		return InstallResult{}, Manifest{}, fmt.Errorf("validate GitHub release manifest: %w", errValidate)
	}
	result, errInstall := c.installRelease(ctx, plugin, release, version, options)
	if errInstall != nil {
		return InstallResult{}, Manifest{}, errInstall
	}
	return result, manifest, nil
}

func normalizeGitHubRepository(repository string) (string, string, error) {
	owner, repo, errParts := GitHubRepositoryParts(repository)
	if errParts != nil {
		return "", "", errParts
	}
	canonical := (&url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/" + owner + "/" + repo,
	}).String()
	return canonical, owner, nil
}

func (c Client) fetchRequestedRelease(ctx context.Context, plugin Plugin, requestedVersion string) (Release, error) {
	requestedVersion = strings.TrimSpace(requestedVersion)
	if requestedVersion == "" {
		release, errLatest := c.FetchLatestRelease(ctx, plugin)
		if errLatest != nil {
			return Release{}, fmt.Errorf("fetch latest GitHub release: %w", errLatest)
		}
		return release, nil
	}
	normalizedVersion := normalizeVersion(requestedVersion)
	if !validPluginVersion(normalizedVersion) {
		return Release{}, fmt.Errorf("invalid plugin version %q", requestedVersion)
	}

	candidates := []string{requestedVersion}
	if strings.HasPrefix(strings.ToLower(requestedVersion), "v") {
		candidates = append(candidates, normalizedVersion)
	} else {
		candidates = append(candidates, "v"+normalizedVersion)
	}
	var errLast error
	seen := make(map[string]struct{}, len(candidates))
	for _, tag := range candidates {
		tag = strings.TrimSpace(tag)
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		release, errRelease := c.FetchReleaseByTag(ctx, plugin, tag)
		if errRelease == nil {
			return release, nil
		}
		errLast = errRelease
	}
	return Release{}, fmt.Errorf("fetch GitHub release for version %q: %w", requestedVersion, errLast)
}

func releasePluginID(release Release, requestedID, version, goos, goarch string) (string, error) {
	requestedID = strings.TrimSpace(requestedID)
	if requestedID != "" {
		if !validPluginID(requestedID) {
			return "", fmt.Errorf("invalid plugin id %q", requestedID)
		}
		if _, _, errAssets := SelectReleaseAssets(release, requestedID, version, goos, goarch); errAssets != nil {
			return "", errAssets
		}
		return requestedID, nil
	}

	suffix := fmt.Sprintf("_%s_%s_%s.zip", version, goos, goarch)
	ids := make([]string, 0, 1)
	seen := make(map[string]struct{})
	for _, asset := range release.Assets {
		name := strings.TrimSpace(asset.Name)
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		id := strings.TrimSuffix(name, suffix)
		if !validPluginID(id) {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("no plugin release asset matching <id>%s", suffix)
	case 1:
		return ids[0], nil
	default:
		return "", fmt.Errorf("multiple plugin ids match the current platform release assets (%s); specify -plugin-id", strings.Join(ids, ", "))
	}
}
