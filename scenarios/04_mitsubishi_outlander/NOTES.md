# Mitsubishi Outlander PHEV Wi-Fi module weak PSK -> GSM module fix

**Source:** Pen Test Partners disclosure (2016); component-swap noted in arXiv:2111.11612

**Summary:** Update replaces the whole telecom component and strengthens auth. Naively expected PASS, but the tool correctly returns FLAG: 'gsm' is a brand-new node with no prior reachability history, so the newly-reachable pair is reported even though the hop is fully SecOC-protected -- a genuinely unreviewed route is not the same claim as a safe one. Worth keeping as-is: this is a case where the tool's actual behavior is more defensible than the intuitive expectation.

**Expected verdict on the update (before -> after):** FLAG
