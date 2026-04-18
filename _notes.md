## Fix

PDF generation failed with `LayoutError` when a single finding's evidence was taller than an A4 page (e.g. the full list of running services or installed software — easily 400+ lines).

Root cause: the evidence was rendered inside a reportlab `Table` cell, and reportlab cannot split a single table cell across pages.

**Fix:** evidence is now emitted as a standalone `Preformatted` flowable outside the surrounding table. reportlab splits that natively, so huge outputs flow cleanly across pages. The coloured severity bar and card look are preserved for the header and body content via a small non-splitting table.

Also raised the in-PDF evidence line cap from 100 to 250; anything above that still gets truncated with a pointer to `scan.log` / `findings.json`.
