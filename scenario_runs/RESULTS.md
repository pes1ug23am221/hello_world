# Scenario test results

| # | Scenario | Expected | Actual | Findings | Categories | Match |
|---|---|---|---|---|---|---|
| 1 | Jeep Cherokee / Uconnect remote exploit (2015) | BLOCK | BLOCK | 4 | newly-reachable, unprotected-new-hop | yes |
| 2 | BMW ConnectedDrive TCU-to-gateway diagnostic passthrough (2018) | BLOCK | BLOCK | 2 | newly-reachable, unprotected-new-hop | yes |
| 3 | Tesla 2016 remote-attack OTA fix: code signing added (control case) | PASS | PASS | 0 | - | yes |
| 4 | Mitsubishi Outlander PHEV Wi-Fi module weak PSK -> GSM module fix | FLAG | FLAG | 3 | component-added, component-removed, newly-reachable | yes |
| 5 | FCA post-recall network-level access restriction (2015) | PASS | PASS | 0 | - | yes |
| 6 | Cloud API authorization-object regression (Sam Curry disclosure, 2023) | BLOCK | BLOCK | 1 | secoc-removed | yes |
| 7 | Spireon fleet admin-panel authentication misconfiguration (2023) | BLOCK | BLOCK | 1 | secoc-removed | yes |
| 8 | SOME/IP service-discovery de-association (Zelle et al., 2021) | BLOCK | BLOCK | 1 | secoc-removed | yes |
| 9 | Third-party supplier SDK bundled into an infotainment feature update | BLOCK | BLOCK | 3 | component-added, newly-reachable, unprotected-new-hop | yes |
