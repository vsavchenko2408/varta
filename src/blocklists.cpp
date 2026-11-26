#include "blocklists.hpp"

namespace varta {

// The lists are deliberately conservative: they target endpoints whose job is telemetry,
// analytics or advertising, not the services themselves (Windows Update, App Store, YouTube...).
// The hosts file has no wildcards, so every host name is listed explicitly.

const std::vector<Category>& builtin_categories() {
    static const std::vector<Category> cats = {
        {"windows",
         "Windows telemetry (Connected User Experiences, Watson error reports)",
         "Windows Defender may flag the hosts file (HostsFileHijack) - see README",
         true,
         {
             "vortex.data.microsoft.com",
             "vortex-win.data.microsoft.com",
             "v10.vortex-win.data.microsoft.com",
             "v10.events.data.microsoft.com",
             "v20.events.data.microsoft.com",
             "self.events.data.microsoft.com",
             "umwatson.events.data.microsoft.com",
             "telemetry.microsoft.com",
             "oca.telemetry.microsoft.com",
             "sqm.telemetry.microsoft.com",
             "watson.telemetry.microsoft.com",
             "telecommand.telemetry.microsoft.com",
             "df.telemetry.microsoft.com",
             "watson.microsoft.com",
             "telemetry.appex.bing.net",
             "telemetry.urs.microsoft.com",
             "settings-sandbox.data.microsoft.com",
             "vortex-sandbox.data.microsoft.com",
             "feedback.windows.com",
             "feedback.search.microsoft.com",
         }},
        {"office",
         "Microsoft Office telemetry",
         "",
         true,
         {
             "nexus.officeapps.live.com",
             "nexusrules.officeapps.live.com",
             "mobile.events.data.microsoft.com",
         }},
        {"apple",
         "Apple analytics and ad measurement",
         "Personalised App Store ads and some usage stats stop working",
         true,
         {
             "xp.apple.com",
             "metrics.icloud.com",
             "metrics.mzstatic.com",
             "iadsdk.apple.com",
             "api-adservices.apple.com",
             "books-analytics-events.apple.com",
             "weather-analytics-events.apple.com",
             "notes-analytics-events.apple.com",
         }},
        {"google",
         "Google Analytics, Tag Manager and ad networks (DoubleClick, AdSense)",
         "Some sites with broken ad scripts may misbehave",
         true,
         {
             "google-analytics.com",
             "www.google-analytics.com",
             "ssl.google-analytics.com",
             "region1.google-analytics.com",
             "googletagmanager.com",
             "www.googletagmanager.com",
             "googletagservices.com",
             "www.googletagservices.com",
             "doubleclick.net",
             "ad.doubleclick.net",
             "stats.g.doubleclick.net",
             "googleads.g.doubleclick.net",
             "googlesyndication.com",
             "pagead2.googlesyndication.com",
             "tpc.googlesyndication.com",
             "googleadservices.com",
             "www.googleadservices.com",
             "adservice.google.com",
             "app-measurement.com",
         }},
        {"meta",
         "Meta/Facebook pixel and Audience Network",
         "'Log in with Facebook' buttons and embedded FB widgets break",
         false,
         {
             "connect.facebook.net",
             "pixel.facebook.com",
             "an.facebook.com",
         }},
        {"analytics",
         "Third-party analytics & session recording (Mixpanel, Segment, Hotjar, Clarity...)",
         "",
         true,
         {
             "api.mixpanel.com",
             "cdn.mxpnl.com",
             "api.segment.io",
             "cdn.segment.com",
             "api.amplitude.com",
             "api2.amplitude.com",
             "cdn.amplitude.com",
             "static.hotjar.com",
             "script.hotjar.com",
             "vars.hotjar.com",
             "clarity.ms",
             "www.clarity.ms",
             "c.clarity.ms",
             "sb.scorecardresearch.com",
             "mc.yandex.ru",
             "mc.yandex.com",
             "bam.nr-data.net",
             "js-agent.newrelic.com",
             "cdn.heapanalytics.com",
             "heapanalytics.com",
             "edge.fullstory.com",
             "rs.fullstory.com",
             "js.hs-analytics.net",
             "track.hubspot.com",
             "stats.wp.com",
             "pixel.wp.com",
         }},
        {"ads",
         "Ad exchanges and social ad trackers (Criteo, Taboola, Outbrain, AppNexus...)",
         "",
         true,
         {
             "adnxs.com",
             "ib.adnxs.com",
             "secure.adnxs.com",
             "criteo.com",
             "static.criteo.net",
             "bidder.criteo.com",
             "taboola.com",
             "cdn.taboola.com",
             "trc.taboola.com",
             "outbrain.com",
             "widgets.outbrain.com",
             "amazon-adsystem.com",
             "aax.amazon-adsystem.com",
             "adsrvr.org",
             "match.adsrvr.org",
             "rubiconproject.com",
             "pubmatic.com",
             "ads.pubmatic.com",
             "px.ads.linkedin.com",
             "analytics.twitter.com",
             "static.ads-twitter.com",
             "analytics.tiktok.com",
         }},
        {"nvidia",
         "NVIDIA GeForce Experience telemetry",
         "",
         true,
         {
             "telemetry.gfe.nvidia.com",
             "events.gfe.nvidia.com",
         }},
        {"linux",
         "Linux distro metrics (Ubuntu metrics/crash reports, popularity-contest)",
         "Ubuntu error reports (apport) are not sent",
         true,
         {
             "metrics.ubuntu.com",
             "popcon.ubuntu.com",
             "daisy.ubuntu.com",
             "popcon.debian.org",
         }},
        {"apps",
         "Developer & app telemetry (Firefox, VS Code / .NET CLI)",
         "",
         true,
         {
             "incoming.telemetry.mozilla.org",
             "dc.services.visualstudio.com",
         }},
    };
    return cats;
}

const Category* find_category(const std::string& id) {
    for (const auto& c : builtin_categories())
        if (c.id == id) return &c;
    return nullptr;
}

const std::vector<std::string>& public_doh_resolvers() {
    static const std::vector<std::string> ips = {
        // Cloudflare
        "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
        // Google
        "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
        // Quad9
        "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
        // OpenDNS
        "208.67.222.222", "208.67.220.220",
        // AdGuard
        "94.140.14.14", "94.140.15.15",
    };
    return ips;
}

}  // namespace varta
