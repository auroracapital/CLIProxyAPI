package pluginstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallGitHubRepositoryInfersIDFromLatestRelease(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	archiveData := makeZip(t, map[string]string{"sample-provider.so": "library-data"})
	archiveName := "sample-provider_1.2.3_linux_amd64.zip"
	checksum := sha256.Sum256(archiveData)
	client := Client{HTTPClient: mapHTTPDoer{
		"https://api.github.com/repos/example/sample-plugin/releases/latest": []byte(`{
			"tag_name": "v1.2.3",
			"assets": [
				{"name": "` + archiveName + `", "browser_download_url": "https://downloads.example/` + archiveName + `"},
				{"name": "checksums.txt", "browser_download_url": "https://downloads.example/checksums.txt"}
			]
		}`),
		"https://downloads.example/" + archiveName: archiveData,
		"https://downloads.example/checksums.txt":  []byte(hex.EncodeToString(checksum[:]) + "  " + archiveName + "\n"),
	}}

	result, manifest, errInstall := client.InstallGitHubRepository(context.Background(), GitHubInstallRequest{
		Repository: "https://github.com/example/sample-plugin/",
		Options: InstallOptions{
			PluginsDir: root,
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
	})
	if errInstall != nil {
		t.Fatalf("InstallGitHubRepository() error = %v", errInstall)
	}
	if result.ID != "sample-provider" || result.Version != "1.2.3" || result.InstallType != InstallTypeGitHubRelease {
		t.Fatalf("result = %#v", result)
	}
	wantPath := filepath.Join(root, "linux", "amd64", "sample-provider-v1.2.3.so")
	if result.Path != wantPath {
		t.Fatalf("Path = %q, want %q", result.Path, wantPath)
	}
	if data, errRead := os.ReadFile(wantPath); errRead != nil || string(data) != "library-data" {
		t.Fatalf("installed plugin = %q, error = %v", data, errRead)
	}
	if manifest.ID != "sample-provider" || manifest.Repository != "https://github.com/example/sample-plugin" || manifest.ReleaseTag != "v1.2.3" {
		t.Fatalf("manifest = %#v", manifest)
	}
	if manifest.SourceID != GitHubSourceID || manifest.SourceName != GitHubSourceName || manifest.SourceURL != manifest.Repository {
		t.Fatalf("manifest source = %#v", manifest)
	}
}

func TestInstallGitHubRepositoryAcceptsVersionWithoutVPrefix(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	archiveData := makeZip(t, map[string]string{"sample-provider.so": "pinned-data"})
	archiveName := "sample-provider_0.3.0_linux_amd64.zip"
	checksum := sha256.Sum256(archiveData)
	client := Client{HTTPClient: mapHTTPDoer{
		"https://api.github.com/repos/example/sample-plugin/releases/tags/v0.3.0": []byte(`{
			"tag_name": "v0.3.0",
			"assets": [
				{"name": "` + archiveName + `", "browser_download_url": "https://downloads.example/` + archiveName + `"},
				{"name": "checksums.txt", "browser_download_url": "https://downloads.example/checksums.txt"}
			]
		}`),
		"https://downloads.example/" + archiveName: archiveData,
		"https://downloads.example/checksums.txt":  []byte(hex.EncodeToString(checksum[:]) + "  " + archiveName + "\n"),
	}}

	result, _, errInstall := client.InstallGitHubRepository(context.Background(), GitHubInstallRequest{
		Repository: "https://github.com/example/sample-plugin",
		Version:    "0.3.0",
		Options: InstallOptions{
			PluginsDir: root,
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
	})
	if errInstall != nil {
		t.Fatalf("InstallGitHubRepository() error = %v", errInstall)
	}
	if result.Version != "0.3.0" {
		t.Fatalf("Version = %q, want 0.3.0", result.Version)
	}
}

func TestInstallGitHubRepositoryRejectsRequestedVersionMismatch(t *testing.T) {
	t.Parallel()

	client := Client{HTTPClient: mapHTTPDoer{
		"https://api.github.com/repos/example/sample-plugin/releases/tags/v1.2.3": []byte(`{
			"tag_name": "v2.0.0",
			"assets": []
		}`),
	}}
	_, _, errInstall := client.InstallGitHubRepository(context.Background(), GitHubInstallRequest{
		Repository: "https://github.com/example/sample-plugin",
		Version:    "v1.2.3",
		Options: InstallOptions{
			PluginsDir: t.TempDir(),
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
	})
	if errInstall == nil || !strings.Contains(errInstall.Error(), "want \"1.2.3\"") {
		t.Fatalf("InstallGitHubRepository() error = %v, want version mismatch", errInstall)
	}
}

func TestReleasePluginIDRequiresOverrideForAmbiguousAssets(t *testing.T) {
	t.Parallel()

	release := Release{Assets: []ReleaseAsset{
		{Name: "alpha_1.0.0_linux_amd64.zip"},
		{Name: "bravo_1.0.0_linux_amd64.zip"},
		{Name: "checksums.txt"},
	}}
	_, errID := releasePluginID(release, "", "1.0.0", "linux", "amd64")
	if errID == nil || !strings.Contains(errID.Error(), "specify -plugin-id") {
		t.Fatalf("releasePluginID() error = %v, want -plugin-id guidance", errID)
	}
	id, errOverride := releasePluginID(release, "bravo", "1.0.0", "linux", "amd64")
	if errOverride != nil || id != "bravo" {
		t.Fatalf("releasePluginID(override) = %q, %v", id, errOverride)
	}
}

func TestInstallGitHubRepositoryRejectsMissingPlatformAsset(t *testing.T) {
	t.Parallel()

	client := Client{HTTPClient: mapHTTPDoer{
		"https://api.github.com/repos/example/sample-plugin/releases/latest": []byte(`{
			"tag_name": "v1.0.0",
			"assets": [{"name": "sample-provider_1.0.0_darwin_arm64.zip"}]
		}`),
	}}
	_, _, errInstall := client.InstallGitHubRepository(context.Background(), GitHubInstallRequest{
		Repository: "https://github.com/example/sample-plugin",
		Options: InstallOptions{
			PluginsDir: t.TempDir(),
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
	})
	if errInstall == nil || !strings.Contains(errInstall.Error(), "no plugin release asset") {
		t.Fatalf("InstallGitHubRepository() error = %v, want missing platform asset", errInstall)
	}
}
