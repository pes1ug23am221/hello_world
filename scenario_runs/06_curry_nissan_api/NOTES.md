# Cloud API authorization-object regression (Sam Curry disclosure, 2023)

**Source:** Sam Curry et al., 'Web Hackers vs. The Auto Industry' (Jan 2023); Nissan statement re: API configuration fix

**Summary:** Backend API loses its per-VIN authorization check, reaching ignition control by VIN alone. Expected: BLOCK (secoc-removed).

**Expected verdict on the update (before -> after):** BLOCK
