// varta-gui - parsing of GitHub release data for the update check (no networking here,
// so the logic can be unit-tested).
#pragma once

#include <QByteArray>
#include <QString>

namespace update {

// The latest release as published on GitHub.
struct ReleaseInfo {
    bool valid = false;
    QString tag;        // "v0.4.0"
    QString version;    // "0.4.0"
    QString notes;      // release description (Markdown)
    QString pageUrl;    // release page on GitHub
    QString assetName;  // download for this platform, empty if none
    QString assetUrl;
    qint64 assetSize = 0;
    QString assetSha256;  // lowercase hex from GitHub's "digest" field, empty if not given
};

// Public GitHub API, no account needed. One anonymous request, nothing about the user is sent.
inline constexpr const char* kLatestReleaseApi =
    "https://api.github.com/repos/vsavchenko2408/varta/releases/latest";

// "v0.4.0", "V0.4.0", "0.4.0" -> "0.4.0"
QString normalizeVersion(const QString& tag);

// True if `remote` is a newer version than `current` (both may carry a "v").
bool isNewerVersion(const QString& remote, const QString& current);

// File-name ending of the download for the running platform:
// "-windows-x64.zip" on Windows, "-macos-x64.zip" on macOS, empty on Linux (release page).
QString platformAssetSuffix();

// Parses the JSON from kLatestReleaseApi and picks the asset whose name ends with
// `assetSuffix` (none is picked when the suffix is empty). Drafts and pre-releases are ignored.
ReleaseInfo parseLatestRelease(const QByteArray& json, const QString& assetSuffix);

}  // namespace update
