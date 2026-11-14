# Browser driver for the conformance suite

A container that plays the end user for the OpenID Foundation conformance suite in a real Chromium, in place of the suite's built-in HtmlUnit browser. It opens the URLs each running test module wants visited, signs in on the test host or confirms a logout there, and waits for the suite's own pages to report back. When a module waits for a screenshot, the driver uploads one to the placeholder the module created.

`run.ps1` builds the image, starts the driver on the suite's network before the plans run, and stops it afterwards. A failure the driver reports fails the run.

## How it talks to the suite

All calls go to the suite's REST API under `CONFORMANCE_SERVER`:

- `GET api/runner/running` lists the modules the suite holds.
- `GET api/info/{id}` returns the module name and status.
- `GET api/runner/{id}` returns `browser.urlsWithMethod`, the URLs still to visit, and `browser.uploadsRequired`, the number of open image placeholders.
- `POST api/runner/browser/{id}/visit?url=...` marks a URL visited. The URL has to match exactly. It is sent before the page opens, in the order the suite's own browser uses.
- `GET api/log/{id}/images` lists log entries with images. An entry carrying an `upload` field is an unfilled placeholder.
- `POST api/log/{id}/images/{placeholder}` takes a `data:image/png;base64,...` or `data:image/jpeg;base64,...` body (`text/plain`). The suite accepts at most 500 KB decoded and two images per test, so the driver falls back from PNG to JPEG to stay under the limit.

The suite publishes a URL in `urlsWithMethod` only when no entry of the configuration's `browser` array matches it, which is why `oidcc.json` has no `browser` array and no per-module overrides.

## Screenshots

The driver uploads only when all of these hold for two polls in a row:

- the module is `WAITING`
- it has no URL left to visit
- it still has an open placeholder

The image comes from the module's most recent visit, from the last page of the server under test seen there:

- a login form is captured before it is filled
- a logout confirmation is clicked, and the page that follows is captured
- any other page that stays put, such as an error page or the signed-out page, is captured as is

If that visit showed no page of the server under test, the module fails in the driver's log rather than receiving an unrelated picture. A module with more than one open placeholder fails the same way.

A module that receives an image ends with the result `REVIEW`, which `run-test-plan.py` counts as a completed module. At certification a person looks at these images.

## Modules from an earlier run

A suite left running keeps its waiting modules indefinitely. The driver notes the modules the suite holds when it starts and leaves them alone, so leftovers of an earlier run are not reported as this run's failures.

## Authentication

None is needed with the compose file `run.ps1` uses: `docker-compose-prebuilt.yml` defaults `SPRING_PROFILES_ACTIVE` to `dev`, which signs every request in as an administrator (`DummyUserFilter`).

Against a suite outside dev mode, set `CONFORMANCE_TOKEN` to an API token created in the suite's web interface, for the user who owns the tests: the image endpoints accept only the test's owner or an administrator.

## Environment variables

- `CONFORMANCE_SERVER` (required): the suite's base URL.
- `HOST_ORIGIN` (required): the origin of the server under test. Its pages are the ones the driver signs in on and captures.
- `LOGIN_EMAIL`, `LOGIN_PASSWORD` (required): typed into the fields `email` and `password` before the button `sign-in` is pressed. `run.ps1` reads them from the test host's `appsettings.json`.
- `DRIVER_DEADLINE_SECONDS` (required): the driver exits with code 1 when this runs out, whatever is in progress.
- `DRIVER_POLL_SECONDS` (default 2): the pause between two reads of the suite's state.
- `DRIVER_PAGE_TIMEOUT_SECONDS` (default 30): the longest wait for a page to load, an element to appear or a page to stop navigating.
- `DRIVER_SETTLE_MS` (default 1500): how long an address has to hold still before the page counts as settled, so that auto-submitting forms move on first.
- `CONFORMANCE_TOKEN` (optional): sent as a bearer token. Not needed in dev mode.
- `DRIVER_SCREENSHOT_DIR` (optional): a directory that receives a copy of every screenshot, for inspection.

## Behavior

- Each test module gets its own browser context, shared by all of that module's visits. A second authorization, a logout after a sign-in and a session check all need the session from the first visit, as in the suite's own browser.
- Modules run concurrently, because the suite runs several modules of a plan at once.
- A URL the suite publishes with method `POST` is opened as a form posted to the URL without its query, with the query parameters as the body.
- On a suite page under `/test/.../callback`, the driver waits for `#submission_complete`. On a `session_verify` page it waits for the address to carry `session_result`.
- A page on any other origin, a login form that returns after two sign-ins, or a page that keeps navigating fails the module in the driver's log. The module then times out in the suite, which reports it.
- On `SIGTERM` the driver stops, prints one summary line per failed module, and exits with 1 if any module failed or 0 otherwise.
