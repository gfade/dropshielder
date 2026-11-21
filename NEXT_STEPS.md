# Dropshielder: what to build next

This file is the work order for wiring real data sources into Dropshielder.
Read all of "Ground rules" and "How the app works" before starting Task 1.

## What exists today

A working sticker shop. A buyer picks a sticker, ticks "Scan this page before
I pay", and clicks Buy. The server runs seven scan steps, sends each step to
the webpage as it finishes, then sends a verdict: SAFE, CAUTION or HOLD.

All seven steps currently return invented data ("mock"). Your job is to
replace the mock data with real API calls, one step at a time. The webpage,
the order flow, the verdict rules and the tests already work and must keep
working.

Run it (from the `dropshielder` folder, no installs needed):

    python -m backend.server            # then open http://127.0.0.1:8080
    python -m unittest discover -s tests -v

## Ground rules

1. Only edit the `live(...)` function in each file under `backend/providers/`.
   Each one currently raises `NotImplementedError`. You may add private helper
   functions (names starting with `_`) in the same file.
2. Do not change `backend/schemas.py`, `backend/verdict.py`, `backend/scan.py`
   or anything in `frontend/`, except where a task below says to.
3. Do not change any `mock(...)` function or `backend/providers/fixtures.py`.
   The tests depend on them.
4. `live(...)` must take the same arguments as `mock(...)` in the same file
   and return the same shape. The shapes are defined in `backend/schemas.py`.
   The first argument, `scenario`, is for mocks only: ignore it in `live`.
5. Never fall back to mock data inside `live`. If the API fails, times out, or
   returns something you cannot parse, raise `ProviderError` with a short
   message:

       from . import ProviderError
       raise ProviderError("OSV returned HTTP 503")

   The scan catches it, marks the step failed, and the verdict becomes at
   least CAUTION. That is the intended behaviour. A scan that hides a failure
   and says SAFE is the worst possible bug in this product.
6. Every network call needs a timeout (use 6 seconds unless a task says
   otherwise).
7. API keys come from environment variables. Never write a key into a file.
   Never print or log a key.
8. Use only the Python standard library (`urllib.request`, `json`) for Tasks
   1 to 4. Tasks 5 to 7 need the Gemini SDK; add it to a new
   `requirements.txt` when you get there.
9. After each task: run the tests (all 18 existing tests must still pass),
   add the new tests the task lists, then switch that one provider on and try
   it in the browser.
10. Do the tasks in order. Finish and test one before starting the next.

## How the app works

    Browser                         Server
    ------------------------------  ---------------------------------------
    POST /api/orders           -->  store.create_order  (status AWAITING_SCAN)
    GET  /api/orders/<id>/scan -->  scan.run_scan       (server-sent events)
        <-- event: step  {id, status: "running", source}
        <-- event: step  {id, status: "done" | "skipped" | "failed", summary, data}
        ... one pair per step ...
        <-- event: report {report, order}
                                    store.apply_report: HOLD -> order HELD,
                                    otherwise order COMPLETED (download unlocks)

The steps, in order (defined in `STEPS` in `backend/scan.py`):

| # | Provider id        | File                             | Question it answers                            |
|---|--------------------|----------------------------------|------------------------------------------------|
| 1 | `inventory`        | `providers/inventory.py`         | What packages and versions does the page run?  |
| 2 | `cve_feed`         | `providers/cve_feed.py`          | Which published CVEs affect those versions?    |
| 3 | `known_exploited`  | `providers/known_exploited.py`   | Are any of the new ones exploited in the wild? |
| 4 | `traffic`          | `providers/traffic.py`           | Does our own traffic show attack attempts?     |
| 5 | `advisory_reader`  | `providers/advisory_reader.py`   | What does each new advisory mean? (model)      |
| 6 | `exposure_analyst` | `providers/exposure_analyst.py`  | Can a web request reach the flaw? (model)      |
| 7 | `decision_gate`    | `providers/decision_gate.py`     | How risky is this, overall? (Decisions API)    |

What "new CVE" means: a CVE whose id is not in `store.ACKNOWLEDGED`. The
merchant adds ids to that set with the "mark CVEs as reviewed" button. The
`cve_feed` provider returns every CVE that affects the installed versions;
`scan.py` works out which are new. Do not filter by date in the provider.

Turning a provider live: set the `DROPSHIELDER_LIVE` environment variable to a
comma-separated list of provider ids, then start the server.

    # PowerShell
    $env:DROPSHIELDER_LIVE = "cve_feed,known_exploited"; python -m backend.server
    # bash
    DROPSHIELDER_LIVE=cve_feed,known_exploited python -m backend.server

Each step on the webpage shows a MOCK or LIVE badge, so you can see which
steps are real. While any step is mock, the "Demo scenario" dropdown stays
visible; it only affects the mock steps.

How to test a `live` function without the network: put the HTTP call in one
small private helper (for example `_post_json(url, body)`), and in the test
replace that helper with `unittest.mock.patch` so it returns a saved response.
Never let a unit test call the real internet.

---

## Task 1: `inventory.live` — list the packages the page runs

File: `backend/providers/inventory.py`

Signature: `live(scenario: str, page_url: str) -> List[Package]`

Returns a list of `{"name", "version", "source"}` dicts. `version` must be an
exact version such as `4.17.21`, with no `^`, `~`, `>=` or spaces.

Dropshielder itself has no JavaScript dependencies, so there is nothing real
to find on its own page. Point the scan at a storefront project instead:

1. Read the environment variable `DROPSHIELDER_PACKAGE_JSON`. It holds the
   path to a storefront's `package.json`. If it is not set or the file does
   not exist, raise `ProviderError("DROPSHIELDER_PACKAGE_JSON is not set or missing")`.
2. Parse the file as JSON. For every entry in its `"dependencies"` object,
   strip leading `^ ~ > = <` and spaces from the version and add
   `{"name": name, "version": cleaned, "source": "package.json"}`.
   Skip entries whose cleaned version does not match the regular expression
   `^\d+\.\d+\.\d+` (for example `"latest"`, `"*"`, git URLs).
3. Also fetch `page_url` with `urllib.request` (timeout 6 seconds, read at
   most 250,000 bytes). Find every `<script src="...">` and `<link href="...">`
   URL. For each URL, try these patterns and record a package when one matches,
   with `source` set to `"<script src> on product page"`:
   - `cdnjs.cloudflare.com/ajax/libs/<name>/<version>/`
   - `cdn.jsdelivr.net/npm/<name>@<version>`
   - `unpkg.com/<name>@<version>`
   If fetching the page fails, do not raise: the `package.json` list is still
   useful. Just return what you have.
4. Remove duplicates (same name and version).

Reference: the old project already has working regular expressions for step 3
in `backend/gemini_pipeline/webpage_cve_verifier.py` (function
`extract_webpage_packages_from_html`). Copy the patterns, not the whole file.
Note that CDN names differ from npm names (`lodash.js` is npm `lodash`,
`twitter-bootstrap` is npm `bootstrap`); that file has a mapping table.

Tests to add (`tests/test_inventory_live.py`):
- A temp `package.json` with `"^1.2.3"`, `"~0.4.0"` and `"latest"` gives two
  packages with versions `1.2.3` and `0.4.0`.
- Missing env var raises `ProviderError`.
- HTML containing a cdnjs script tag yields that package (patch the fetch helper).

Done when: with `DROPSHIELDER_LIVE=inventory` and the env var pointing at a
real `package.json`, the first step on the webpage shows a LIVE badge and the
real package count.

## Task 2: `cve_feed.live` — look up CVEs on OSV.dev

File: `backend/providers/cve_feed.py`

Signature: `live(scenario: str, packages: List[Package]) -> List[Cve]`

Returns a list of dicts with exactly these keys: `id`, `package`, `version`,
`severity`, `summary`, `published`, `fixed_version`, `url`. Do not set
`is_new`, `known_exploited` or `reachable`; `scan.py` sets those.

OSV.dev is Google's open vulnerability database. It needs no API key.

1. Send one batch query:

       POST https://api.osv.dev/v1/querybatch
       Content-Type: application/json
       {"queries": [
         {"package": {"name": "<name>", "ecosystem": "npm"}, "version": "<version>"},
         ...one per package, in the same order as `packages`...
       ]}

   The response is `{"results": [ {"vulns": [{"id": "...", "modified": "..."}]}, ... ]}`.
   `results[i]` belongs to `packages[i]`. A result with no `vulns` key means
   no known vulnerabilities for that package.
   If the HTTP status is not 200, raise `ProviderError`.
2. The batch response has only ids. For each id, fetch the details:

       GET https://api.osv.dev/v1/vulns/<id>

   Fetch at most 25 ids per scan (take them in order) so the scan stays fast.
   Use a `concurrent.futures.ThreadPoolExecutor(max_workers=8)` to fetch them
   in parallel. If one detail request fails, raise `ProviderError`: a partial
   CVE list would make the scan look cleaner than it is.
3. Build each `Cve` from the detail JSON:
   - `id`: if the detail's `aliases` list contains a string starting with
     `CVE-`, use the first such string. Otherwise use the OSV id (often
     `GHSA-...`).
   - `package`, `version`: from the package you queried.
   - `summary`: the `summary` field; if missing, the first 160 characters of
     `details`. Truncate to 160 characters.
   - `published`: the first 10 characters of the `published` field
     (`"2026-11-19T08:00:00Z"` becomes `"2026-11-19"`).
   - `severity`: `database_specific.severity` upper-cased if present and one
     of `LOW`, `MODERATE`, `HIGH`, `CRITICAL`; otherwise `"MODERATE"`.
   - `fixed_version`: look in `affected[]` for the entry whose
     `package.name` equals the package name, then in its
     `ranges[].events[]` for the first event with a `fixed` key. Use `""` if
     there is none.
   - `url`: `https://nvd.nist.gov/vuln/detail/<id>` when `id` starts with
     `CVE-`, otherwise `https://osv.dev/vulnerability/<osv id>`.
4. Remove duplicates: the same `(id, package)` pair must appear once.
5. If `packages` is empty, return `[]` without calling the API.

Reference: `query_osv_proven_cves_live` in the old project's
`backend/gemini_pipeline/webpage_cve_verifier.py` does most of this with
`httpx`. Rewrite it with `urllib.request`. Do not copy its `[:3]` cap per
package or its `except Exception: pass`; both hide results.

Tests to add (`tests/test_cve_feed_live.py`), with the HTTP helper patched:
- Two packages, one with one vuln and one with none, returns one `Cve` with
  all eight keys.
- A GHSA id whose detail has a `CVE-` alias is returned under the CVE id.
- `querybatch` returning HTTP 500 raises `ProviderError`.
- Empty `packages` returns `[]` and makes no HTTP call.

Done when: with `DROPSHIELDER_LIVE=inventory,cve_feed` the second step is
LIVE and lists real CVE ids. The first scan will mark all of them as new,
because the acknowledged list only contains a mock id. That is correct: click
"Merchant: mark CVEs as reviewed", buy again, and they should no longer be new.

Then make the acknowledged list survive a restart (this is the one permitted
edit to `backend/store.py`): load `ACKNOWLEDGED` from `data/acknowledged.json`
at import if the file exists, and write the file inside `acknowledge()`.
Keep `fixtures.SEED_ACKNOWLEDGED` as the starting value when the file is absent.

## Task 3: `known_exploited.live` — check the CISA KEV catalogue

File: `backend/providers/known_exploited.py`

Signature: `live(scenario: str, cve_ids: List[str]) -> List[str]`

Returns the subset of `cve_ids` that are listed as exploited in the wild.

CISA publishes the Known Exploited Vulnerabilities (KEV) catalogue as one JSON
file. It needs no API key. The address used at the time of writing was:

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Confirm that address still works before you rely on it (open it in a browser
or with curl). If it has moved, search cisa.gov for "KEV catalog JSON".

1. Download the file (timeout 10 seconds; it is about 1 MB).
2. It looks like `{"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "...", ...}, ...]}`.
   Build a `set` of every `cveID`.
3. Cache that set in a module-level variable together with the time you
   fetched it. Reuse the cache for one hour so each scan does not download
   the file again.
4. Return `[i for i in cve_ids if i in kev_set]`.
5. If the download fails and there is no cached copy, raise `ProviderError`.
   If the download fails but a cached copy exists, use the cached copy.

Limitation to keep in mind: KEV only contains `CVE-` ids. A `GHSA-` id will
never match, which is why Task 2 prefers the CVE alias.

Tests to add (`tests/test_known_exploited_live.py`), with the download patched:
- Ids in the feed are returned; ids not in the feed are not.
- A second call within the hour does not download again.
- Download failure with an empty cache raises `ProviderError`.

Done when: step 3 shows LIVE. Most npm CVEs are not in KEV, so "None listed"
is the normal result.

## Task 4: `traffic.live` — find attack attempts in our own requests

File: `backend/providers/traffic.py`

Signature: `live(scenario: str, cves: List[Cve], window_minutes: int) -> List[Signal]`

Returns a list of `Signal` dicts (see `backend/schemas.py`): `kind`, `path`,
`sample`, `count`, `first_seen`, `last_seen`, `matched_cve`, `confidence`.

This task has three parts. The server does not record requests yet, so
part A adds that.

### Part A: record requests (edit `backend/server.py`)

1. Create `backend/requestlog.py` containing:
   - a `collections.deque(maxlen=5000)` named `LOG`,
   - a `threading.Lock`,
   - `record(method, path, query, body_text, client)` which appends
     `{"ts": <time.time()>, "method", "path", "query", "body", "client"}`,
     with `body` truncated to 2,000 characters,
   - `recent(window_minutes)` which returns a list copy of the entries whose
     `ts` is within the window.
2. In `backend/server.py`, call `requestlog.record(...)` at the top of
   `do_GET` and `do_POST`. `client` is `self.client_address[0]`. `query` is
   `urlparse(self.path).query`. For POST, record the raw body text.
   Do not record requests whose path starts with `/static/`.

### Part B: normalise each request before matching

Attackers hide payloads with encoding. Before matching, turn the query and
body into a canonical string:

1. URL-decode twice (`urllib.parse.unquote_plus` applied two times). This
   turns `%252e%252e%252f` into `../`.
2. `unicodedata.normalize("NFKC", text)`, then replace look-alike letters
   (Cyrillic `Е` to Latin `E`, fullwidth `／` to `/`, and so on).
3. Remove SQL comments (`/* ... */`), replace `\` with `/`, collapse repeated
   `/` and whitespace, and lower-case.

The old project has this already written and working in `backend/normalizer.py`
(function `normalize_input_twice`). Copy that file into
`backend/normalizer.py` here and use it. It returns an object with
`canonical_text`, `has_sql_structure` and `has_traversal_structure`.

### Part C: turn matches into signals

1. For each recent request, normalise `query + "&" + body`.
2. Classify:
   - `has_traversal_structure` is true: kind `path_traversal`.
   - `has_sql_structure` is true: kind `sqli`.
   - otherwise: not a signal.
   The structural patterns are deliberately strict. A shopper searching for
   "Drop Table Dino" or named "O'Brien" must not match. Do not add a pattern
   that matches single words such as `select`, `union`, `drop` or a lone `'`.
3. Group matches by `(kind, path)`. For each group produce one `Signal`:
   - `count`: number of matching requests,
   - `sample`: the raw (not normalised) query of the first match, truncated
     to 200 characters,
   - `first_seen`, `last_seen`: ISO timestamps in UTC,
   - `matched_cve`: the `id` of the first CVE in `cves` whose `attack_shape`
     or `summary` mentions the kind (for `path_traversal`, look for
     "travers" or "../"; for `sqli`, look for "sql" or "inject"). Use `None`
     if nothing matches.
   - `confidence`: `0.6` for a single request, `0.85` for 2 to 4 requests,
     `0.95` for 5 or more. (`verdict.py` holds the order at 0.80 or above,
     so one odd request warns and a burst holds.)
4. Return `[]` when nothing matches.

Tests to add (`tests/test_traffic_live.py`). Fill `requestlog.LOG` directly:
- Five requests with `template=%252e%252e%252f.env` on `/apps/size-chart`
  give one `path_traversal` signal, count 5, confidence 0.95.
- `q=Drop+Table+Dino` and `buyerName=Aoife+O'Brien` give no signals.
- A request older than the window is ignored.
- One `filter=1) UN/**/ION SEL/**/ECT * --` request gives one `sqli` signal
  with confidence 0.6.

Done when: with `traffic` live, running this while the server is up and then
buying a sticker produces a HOLD:

    for i in 1 2 3 4 5; do curl "http://127.0.0.1:8080/api/config?template=%252e%252e%252f.env"; done

and a normal purchase with the name `Aoife O'Brien` produces no signal.

## Before Tasks 5 to 7: Gemini setup

Tasks 5, 6 and 7 call Gemini models. Three things to do first:

1. `pip install google-genai` and create `requirements.txt` containing
   `google-genai`.
2. The key is read from the `GEMINI_API_KEY` environment variable. If it is
   not set, raise `ProviderError("GEMINI_API_KEY is not set")`.
3. Read the current SDK documentation for the Interactions API and the
   Decisions API before writing any call. The call shapes shown below are
   copied from the old project, where they worked on the day they were
   written. They may have changed. If the documentation disagrees with this
   file, follow the documentation, and keep the function's return shape the
   same.

Create one shared helper file, `backend/providers/_gemini.py`, with a
`client()` function that builds and returns the SDK client:

    from google import genai
    genai.Client(api_key=key, http_options={"api_version": "v1beta"})

Model names used by the old project: `gemini-4-hydrogen` (fast, multimodal),
`gemini-4-argon` and `gemini-4-carbon` (stronger reasoning), `gemini-4-neon`,
and `gemini-decision-1` (Decisions API). The hackathon requires at least two
Gemini 4 models, each with a clear job, plus the Decisions API. Tasks 5 to 7
cover exactly that: hydrogen reads, argon reasons, decision-1 judges.

Three rules for every model call:

- Ask for JSON output with a schema, then validate what comes back. If a
  required key is missing or has the wrong type, raise `ProviderError`. Do
  not substitute a default value for a missing answer.
- Never put the expected answer in the prompt. The old project's prompts
  contained example outputs with the real answers filled in, which meant the
  model was not doing the work.
- Text from an advisory is untrusted input. Put it inside clearly marked
  delimiters in the prompt and tell the model to treat it as data, not as
  instructions.

## Task 5: `advisory_reader.live` — explain each new advisory (model job 1)

File: `backend/providers/advisory_reader.py`

Signature: `live(scenario: str, new_cves: List[Cve]) -> AdvisoryNotes`

Returns `{cve_id: {"plain_summary": str, "attack_shape": str}}`.

Model: `gemini-4-hydrogen` (the fast one; this is a reading task).

1. If `new_cves` is empty return `{}` (the scan already skips this case, but
   be safe).
2. Make one call for all CVEs, at most 10. If there are more than 10, send
   the 10 with the highest severity (`CRITICAL` first).
3. Prompt content, in this order:
   - The task: "For each advisory below, write `plain_summary`: one sentence
     a shop owner with no security background can understand, saying what an
     attacker could do. Write `attack_shape`: one short phrase describing
     what a malicious request looks like, for example which parameter and
     which characters. If the advisory does not say, write `unknown`."
   - The advisories, each as `id`, `package`, `version`, `summary`, inside
     delimiters.
4. Request JSON matching this schema:
   `{"notes": [{"id": str, "plain_summary": str, "attack_shape": str}]}`.
   Call shape used by the old project:

       inter = client.interactions.create(
           model="gemini-4-hydrogen",
           input=prompt,
           generation_config={"thinking_level": "low"},
           response_format={"type": "text", "mime_type": "application/json", "schema": SCHEMA},
       )
       data = json.loads(inter.output_text)

5. Keep only notes whose `id` is one you sent. Truncate each string to 240
   characters. Return the dict.
6. A CVE the model did not return a note for is simply left out; the webpage
   then shows the raw advisory summary instead.

Tests to add (patch the model call helper): a normal response maps to the
right dict; a note with an id you did not send is dropped; a response that is
not valid JSON raises `ProviderError`.

## Task 6: `exposure_analyst.live` — can a request reach the flaw? (model job 2)

File: `backend/providers/exposure_analyst.py`

Signature: `live(scenario: str, new_cves: List[Cve], packages: List[Package]) -> ExposureNotes`

Returns `{cve_id: {"reachable": bool, "routes": [str], "why": str}}`.

Model: `gemini-4-argon` (the reasoning one; this is a judgement task).

The model can only judge reachability if you give it evidence. Collect the
evidence in code first, then ask the model to reason over it.

1. Read `DROPSHIELDER_STOREFRONT_DIR` (the folder that contains the
   `package.json` from Task 1). If it is not set, raise `ProviderError`.
2. For each new CVE's package, find the source files that import it: walk the
   folder (skip `node_modules`), and in every `.ts`, `.tsx`, `.js`, `.jsx`
   file look for `from "<package>"`, `from '<package>'`, `require("<package>")`
   or `require('<package>')`.
3. For each importing file, record its path relative to the storefront folder
   and the first 60 lines of the file.
4. Send the model, per CVE: the advisory `summary` and `attack_shape` (from
   Task 5, already on the dict), and the list of importing files with their
   excerpts. State clearly when a package has zero importing files.
5. Ask for, per CVE: `reachable` (true if any importing file is a web route
   handler that passes request input to the package; false if no file
   imports it, or only scripts and command-line tools do), `routes` (for
   example `"GET /apps/size-chart"`, derived from the route file name), and
   `why` (one sentence naming the file).
6. Use `generation_config={"thinking_level": "high"}` and the same JSON
   schema approach as Task 5.
7. One hard rule in code, not left to the model: if a package has zero
   importing files, set `reachable` to `False` yourself with
   `why = "No source file imports this package."` and do not send it to the
   model.
8. If the model omits a CVE, leave it out of the result. The verdict then
   treats it as "not assessed", which counts as CAUTION. Do not guess.

Test data: the old project's `storefront/` folder is a ready-made example.
`xml2js` is imported only by `app/lib/legacy-invoice-cli.ts` (not a route),
so it must come back `reachable: False`.

Tests to add: the import finder on a temp folder (one route file importing a
package, one package imported nowhere); the zero-importers rule returns
`False` without calling the model; malformed model output raises
`ProviderError`.

## Task 7: `decision_gate.live` — one calibrated judgement (Decisions API)

File: `backend/providers/decision_gate.py`

Signature: `live(scenario: str, new_cves: List[Cve], signals: List[Signal]) -> Decision`

Returns `{"exploitation_likely": float 0..1, "confidence": float 0..1,
"risk_score": int 0..4, "rationale": str}`.

Model: `gemini-decision-1` through the Decisions API. The Decisions API
answers fixed questions with calibrated probabilities instead of free text.

1. Build one text block of evidence:
   - for each new CVE: id, package, severity, `reachable`, `routes`,
     `known_exploited`, `attack_shape`;
   - for each signal: kind, path, count, time span, sample, `matched_cve`.
2. Ask two questions. Call shape used by the old project (see its
   `backend/gemini_pipeline/decisions_gate.py` for a full working example):

       res = client.decisions.create(
           model="gemini-decision-1",
           input=evidence_text,
           questions={
               "exploitation_in_progress": {
                   "type": "noul",
                   "instructions": "Is someone actively attempting to exploit a vulnerability on this store right now, as opposed to ordinary shoppers browsing and buying?",
               },
               "checkout_risk": {
                   "type": "score",
                   "instructions": "Score the risk of letting this checkout complete, from 0 to 4.",
                   "criteria": [
                       "0: Nothing new and no suspicious traffic",
                       "1: New CVE that no web route can reach",
                       "2: New reachable CVE with no attack traffic",
                       "3: Attack traffic that may target a reachable flaw",
                       "4: Attack traffic clearly targeting a new reachable flaw",
                   ],
               },
           },
       )

   In the old project each answer exposed `.noul` (probability, for `noul`
   questions), `.score` (for `score` questions) and `.confidence`. Check the
   documentation for the current field names.
3. Map the answers:
   - `exploitation_likely` = the `noul` probability of
     `exploitation_in_progress`,
   - `risk_score` = the `checkout_risk` score, rounded and clamped to 0..4,
   - `confidence` = the lower of the two answers' confidences,
   - `rationale` = a sentence you build in code, for example
     `"Gate: exploitation 0.96, risk 4/4."` (the Decisions API returns
     numbers, not prose).
4. Do not change the thresholds here. `backend/verdict.py` decides what the
   numbers mean: risk 3 or more with confidence 0.70 or more holds the order.

Tests to add: answers map to the right dict; a score of 4.6 clamps to 4; a
missing answer raises `ProviderError`.

Done when (Tasks 5 to 7 together): with
`DROPSHIELDER_LIVE=inventory,cve_feed,known_exploited,traffic,advisory_reader,exposure_analyst,decision_gate`
every step shows LIVE, the "Demo scenario" dropdown disappears by itself, and
the verdict card no longer shows the "steps used mock data" note.

---

## After the seven tasks

These are separate pieces of work. Do them only when asked.

### A. Lock down the merchant actions

`POST /api/orders/<id>/resolve` and `POST /api/acknowledge` are merchant
actions but anyone can call them. Add a `DROPSHIELDER_MERCHANT_TOKEN`
environment variable and require the header
`Authorization: Bearer <token>` on both routes (compare with
`hmac.compare_digest`). Move the three "Merchant:" buttons off the buyer's
page onto a separate `/merchant` page that asks for the token.

### B. Scan speed

Steps run one after another. Steps 3 and 4 do not depend on each other, and
neither do steps 5 and 6. If scans take more than about 8 seconds with live
providers, run each of those pairs in parallel with a thread pool inside
`scan.py`. Keep the order of events on the page the same.

### C. Measure it honestly

The old project's accuracy numbers came from a test set built from ten
repeated templates that were also in the training data. Do not reuse those
numbers. Build a test set for the `traffic` provider like this:

- Benign: at least 300 distinct requests. Include real product searches,
  names with apostrophes and accents, searches that contain SQL words
  ("select", "union", "drop table"), pasted URLs, emoji, very long inputs.
- Attacks: at least 100 distinct payloads across SQL injection and path
  traversal, with plain, single-encoded, double-encoded, mixed-case,
  comment-split and look-alike-letter variants.
- Hold back attack classes the detector was never built for (server-side
  request forgery, template injection, GraphQL introspection) and report the
  miss rate on them separately.
- Baseline: the same requests through one plain regular expression, and
  through one single model call asked "is this an attack?".

Report, for Dropshielder and each baseline: how many attacks were caught, how
many shoppers were wrongly flagged, and every individual miss.

### D. Known limits to state openly

- Version detection reads `package.json` and CDN URLs. Bundled or self-hosted
  scripts are not seen.
- "Reachable" is a model's judgement over import evidence, not a proof.
- Traffic matching covers SQL injection and path traversal only.
- Orders, the request log and (until Task 2's last step) the acknowledged
  list are in memory and reset on restart.
- Payment is not real.
