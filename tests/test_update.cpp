// Tests for the GUI update check: version comparison and GitHub release JSON parsing.
#include <cstdio>

#include "updateinfo.hpp"

static int failures = 0, checks = 0;
#define CHECK(x)                                                         \
    do {                                                                 \
        ++checks;                                                        \
        if (!(x)) {                                                      \
            ++failures;                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);     \
        }                                                                \
    } while (0)

int main() {
    using namespace update;

    CHECK(normalizeVersion("v0.4.0") == "0.4.0");
    CHECK(normalizeVersion(" V1.2 ") == "1.2");
    CHECK(isNewerVersion("v0.4.1", "0.4.0"));
    CHECK(isNewerVersion("0.10.0", "0.9.9"));  // numeric, not alphabetical
    CHECK(!isNewerVersion("v0.4.0", "0.4.0"));
    CHECK(!isNewerVersion("0.3.9", "0.4.0"));
    CHECK(!isNewerVersion("garbage", "0.4.0"));

    const QByteArray json = R"({
      "tag_name": "v0.5.0", "draft": false, "prerelease": false,
      "html_url": "https://github.com/vsavchenko2408/varta/releases/tag/v0.5.0",
      "body": "## Changes",
      "assets": [
        {"name": "Varta-0.5.0-linux-x86_64.tar.gz", "size": 10,
         "browser_download_url": "https://example/linux"},
        {"name": "Varta-0.5.0-windows-x64.zip", "size": 1234,
         "digest": "sha256:ABCDEF0123",
         "browser_download_url": "https://example/win"}
      ]})";
    ReleaseInfo r = parseLatestRelease(json, "-windows-x64.zip");
    CHECK(r.valid);
    CHECK(r.version == "0.5.0");
    CHECK(r.notes == "## Changes");
    CHECK(r.assetName == "Varta-0.5.0-windows-x64.zip");
    CHECK(r.assetUrl == "https://example/win");
    CHECK(r.assetSize == 1234);
    CHECK(r.assetSha256 == "abcdef0123");

    ReleaseInfo none = parseLatestRelease(json, QString());
    CHECK(none.valid && none.assetUrl.isEmpty());

    CHECK(!parseLatestRelease(R"({"tag_name":"v9.0.0","prerelease":true})", "").valid);
    CHECK(!parseLatestRelease("not json", "").valid);
    CHECK(!parseLatestRelease(R"({"tag_name":"latest"})", "").valid);

    std::printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
