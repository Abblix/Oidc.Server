"""Drives a real Chromium through the front-channel steps of OpenID Foundation conformance suite test modules.

The suite publishes, for each running test module, the URLs a browser has to visit when no scripted HtmlUnit
automation in the test configuration matches them. This driver opens those URLs, signs in on the server under
test, confirms a logout, waits until the suite's own pages report completion, tells the suite the URL was visited,
and fills an image placeholder with a real screenshot when a module waits for one.

One browser context per test module: a module visits several URLs in one session (a second authorization, a
logout after a sign-in, a session check), exactly as the suite's own HtmlUnit browser shares its cookies between
the visits of one module.

Every action prints one line. A state the driver does not recognise fails that module loudly and is counted; the
process exits non-zero when any module failed, and stops at the deadline whatever happens.
"""

from __future__ import annotations

import asyncio
import base64
import html
import os
import re
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import httpx
from playwright.async_api import Browser, BrowserContext, Page, async_playwright
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

# ImageAPI.UPLOAD_SIZE_LIMIT: the decoded image may not exceed this many bytes
UPLOAD_SIZE_LIMIT = 500 * 1024

# TestModule.Status values that end a module
FINAL_STATES = {"FINISHED", "INTERRUPTED"}

# The suite renders implicitCallback.html for its redirect endpoints and adds this element once the response has
# been submitted back to the test module
SUBMISSION_COMPLETE_SELECTOR = "#submission_complete"

# The most page transitions one visit may take before the driver gives up on it
MAX_STEPS_PER_VISIT = 15

# The most sign-ins one visit may perform: a third login form means the credentials are not accepted
MAX_SIGN_INS_PER_VISIT = 2


class ModuleFailure(Exception):
    """A state the driver does not know how to continue from; fails the current module."""


def log(scope: str, action: str, detail: str = "") -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    print(f"{stamp} [{scope}] {action} {detail}".rstrip(), flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"driver: environment variable {name} is required and is empty or missing")
    return value


def positive_number_env(name: str, default: float | None = None) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        if default is None:
            raise SystemExit(f"driver: environment variable {name} is required and is empty or missing")
        return default
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(f"driver: environment variable {name} must be a number, got '{raw}'") from None
    if value <= 0:
        raise SystemExit(f"driver: environment variable {name} must be positive, got '{raw}'")
    return value


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


@dataclass(frozen=True)
class Settings:
    suite_url: str
    host_origin: str
    login_email: str
    login_password: str
    api_token: str | None
    deadline_seconds: float
    poll_seconds: float
    page_timeout_ms: float
    settle_ms: float
    screenshot_dir: str | None

    @property
    def suite_origin(self) -> str:
        return origin_of(self.suite_url)

    @staticmethod
    def from_environment() -> "Settings":
        suite_url = required_env("CONFORMANCE_SERVER")
        if not suite_url.endswith("/"):
            suite_url += "/"
        host_origin = origin_of(required_env("HOST_ORIGIN"))
        return Settings(
            suite_url=suite_url,
            host_origin=host_origin,
            login_email=required_env("LOGIN_EMAIL"),
            login_password=required_env("LOGIN_PASSWORD"),
            api_token=os.environ.get("CONFORMANCE_TOKEN", "").strip() or None,
            deadline_seconds=positive_number_env("DRIVER_DEADLINE_SECONDS"),
            poll_seconds=positive_number_env("DRIVER_POLL_SECONDS", 2),
            page_timeout_ms=positive_number_env("DRIVER_PAGE_TIMEOUT_SECONDS", 30) * 1000,
            settle_ms=positive_number_env("DRIVER_SETTLE_MS", 1500),
            screenshot_dir=os.environ.get("DRIVER_SCREENSHOT_DIR", "").strip() or None,
        )


@dataclass
class Screenshot:
    data_uri: str
    size: int
    page_url: str
    kind: str
    facts: PageFacts


@dataclass
class PageFacts:
    """What a captured page of the server under test shows, read from its structure when it was captured."""
    login_form: bool
    client_logo: str | None
    client_policy: str | None
    client_terms: str | None


# What the page a module waits to see has to show, by module, so a run fails on a wrong page rather than handing it
# to a reviewer: a second sign-in for the modules that make the server ask again, the client's registered logo,
# policy and terms on the login page, and for a bad request or a logout a page of the server that is not a login form,
# rather than a redirect back to the client
def expectation_for(module: str):
    if module in ("oidcc-prompt-login", "oidcc-max-age-1"):
        return "a login form", lambda shot: shot.facts.login_form
    if module == "oidcc-registration-logo-uri":
        return "the client's logo", lambda shot: bool(shot.facts.client_logo)
    if module == "oidcc-registration-policy-uri":
        return "a link to the client's policy", lambda shot: bool(shot.facts.client_policy)
    if module == "oidcc-registration-tos-uri":
        return "a link to the client's terms", lambda shot: bool(shot.facts.client_terms)
    if module in ("oidcc-ensure-redirect-uri-in-authorization-request", "oidcc-redirect-uri-query-mismatch",
                  "oidcc-redirect-uri-query-added", "oidcc-ensure-registered-redirect-uri") \
            or module.startswith("oidcc-rp-initiated-logout"):
        return "a page of the server that is not a login form", \
            lambda shot: shot.kind == "server page" and not shot.facts.login_form
    return None


@dataclass
class VisitResult:
    last_server_page: Screenshot | None


class SuiteApi:
    """The suite's REST endpoints this driver uses; each name matches the operationId in the suite source."""

    def __init__(self, settings: Settings):
        headers = {}
        if settings.api_token:
            headers["Authorization"] = f"Bearer {settings.api_token}"
        # The suite runs behind nginx with a self-signed certificate
        self._client = httpx.AsyncClient(base_url=settings.suite_url, headers=headers, verify=False, timeout=30)

    async def close(self) -> None:
        await self._client.aclose()

    async def list_running_test_ids(self) -> list[str]:
        # TestRunner.getAllRunningTestIds: GET /api/runner/running
        response = await self._client.get("api/runner/running")
        self._expect(response, 200, "list running tests")
        return list(response.json())

    async def get_test_info(self, test_id: str) -> dict | None:
        # TestInfoApi.getTestInfo: GET /api/info/{id}; carries testName and status
        response = await self._client.get(f"api/info/{test_id}")
        if response.status_code == 404:
            return None
        self._expect(response, 200, f"read test info of {test_id}")
        return response.json()

    async def get_test_status(self, test_id: str) -> dict | None:
        # TestRunner.getTestStatus: GET /api/runner/{id}; carries browser.urlsWithMethod and browser.uploadsRequired
        response = await self._client.get(f"api/runner/{test_id}")
        if response.status_code == 404:
            return None
        self._expect(response, 200, f"read runner state of {test_id}")
        return response.json()

    async def mark_visited(self, test_id: str, url: str) -> None:
        # TestRunner.visitBrowserUrl: POST /api/runner/browser/{id}/visit?url=..., matched by exact string
        response = await self._client.post(f"api/runner/browser/{test_id}/visit", params={"url": url})
        self._expect(response, 204, f"mark {url} visited")

    async def list_images(self, test_id: str) -> list[dict]:
        # ImageAPI.getAllImages: GET /api/log/{id}/images; an unfilled placeholder is an entry with an 'upload' field
        response = await self._client.get(f"api/log/{test_id}/images")
        self._expect(response, 200, f"list images of {test_id}")
        return list(response.json())

    async def fill_placeholder(self, test_id: str, placeholder: str, data_uri: str) -> None:
        # ImageAPI.uploadTestImageToPlaceholder: POST /api/log/{id}/images/{placeholder}, body is the data URI
        response = await self._client.post(
            f"api/log/{test_id}/images/{placeholder}",
            content=data_uri.encode("ascii"),
            headers={"Content-Type": "text/plain"},
        )
        self._expect(response, 200, f"upload to placeholder {placeholder}")
        # A 200 with an empty body means no unfilled placeholder by that id existed, so nothing was stored
        if not response.content.strip() or response.json() is None:
            raise ModuleFailure(f"the suite stored nothing for placeholder {placeholder}: no unfilled placeholder by that id")

    @staticmethod
    def _expect(response: httpx.Response, status: int, what: str) -> None:
        if response.status_code != status:
            body = response.text[:300].replace("\n", " ")
            raise ModuleFailure(f"suite API could not {what}: HTTP {response.status_code}, expected {status}: {body}")


class ModuleDriver:
    """Carries one test module through every URL it publishes, in one browser context, until it ends."""

    def __init__(self, test_id: str, settings: Settings, api: SuiteApi, browser: Browser):
        self.test_id = test_id
        self.settings = settings
        self.api = api
        self.browser = browser
        self.scope = test_id
        self.module_name = ""
        self.marked_urls: set[str] = set()
        self.filled_placeholders: set[str] = set()
        self.last_visit: VisitResult | None = None
        self.upload_ready_polls = 0

    async def run(self) -> None:
        context = await self.browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
        context.set_default_timeout(self.settings.page_timeout_ms)
        missing_info_polls = 0
        try:
            while True:
                info = await self.api.get_test_info(self.test_id)
                if info is None:
                    # The runner lists a module a moment before its test info is stored
                    missing_info_polls += 1
                    if missing_info_polls > 5:
                        raise ModuleFailure("the runner lists this module, but the suite keeps no test info for it")
                    await asyncio.sleep(self.settings.poll_seconds)
                    continue
                self.module_name = info.get("testName", "")
                self.scope = f"{self.module_name or '?'} {self.test_id}"
                status = info.get("status")
                if not status:
                    raise ModuleFailure("the suite's test info carries no status")
                if status in FINAL_STATES:
                    log(self.scope, "end", f"status {status}, result {info.get('result')}")
                    return

                runner = await self.api.get_test_status(self.test_id)
                if runner is None:
                    log(self.scope, "end", "the runner no longer holds this module")
                    return
                browser_state = runner.get("browser") or {}
                pending = browser_state.get("urlsWithMethod") or []

                if pending:
                    self.upload_ready_polls = 0
                    target = pending[0]
                    await self.visit(context, target["url"], (target.get("method") or "GET").upper())
                    continue

                uploads_required = int(browser_state.get("uploadsRequired") or 0)
                if status == "WAITING" and uploads_required > 0:
                    # The module waits on a placeholder and asks for no further URL; two polls in a row rule out
                    # the moment between one visit finishing and the module publishing its next URL
                    self.upload_ready_polls += 1
                    if self.upload_ready_polls >= 2:
                        await self.upload_screenshot()
                        self.upload_ready_polls = 0
                else:
                    self.upload_ready_polls = 0

                await asyncio.sleep(self.settings.poll_seconds)
        finally:
            await context.close()

    async def visit(self, context: BrowserContext, url: str, method: str) -> None:
        if url in self.marked_urls:
            raise ModuleFailure(f"the suite still lists {url} after it was marked visited")
        log(self.scope, "visit", f"{method} {url}")
        # The suite's own runner marks the URL visited before it opens it (BrowserControl.WebRunner.call)
        await self.api.mark_visited(self.test_id, url)
        self.marked_urls.add(url)

        page = await context.new_page()
        try:
            if method == "POST":
                await self.open_with_post(page, url)
            elif method == "GET":
                await page.goto(url, wait_until="load")
            else:
                raise ModuleFailure(f"the suite asks for HTTP method {method}, which the driver does not send")
            self.last_visit = await self.walk(page)
        except PlaywrightTimeoutError as error:
            raise ModuleFailure(f"timed out on {page.url}: {error.message.splitlines()[0]}") from error
        except PlaywrightError as error:
            raise ModuleFailure(f"browser error on {page.url}: {error.message.splitlines()[0]}") from error
        finally:
            await page.close()

    async def open_with_post(self, page: Page, url: str) -> None:
        # The query string becomes a form body posted to the URL without it, as the suite's own runner does
        parts = urlsplit(url)
        action = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        inputs = "".join(
            f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(value)}">'
            for name, value in parse_qsl(parts.query, keep_blank_values=True)
        )
        await page.set_content(f'<form method="post" action="{html.escape(action)}">{inputs}</form>')
        async with page.expect_navigation(wait_until="load"):
            await page.evaluate("document.forms[0].submit()")

    async def walk(self, page: Page) -> VisitResult:
        """Follows the page from the server under test back to the suite, acting on each page it recognises."""
        sign_ins = 0
        last_server_page: Screenshot | None = None
        for _ in range(MAX_STEPS_PER_VISIT):
            await self.settle(page)
            current = page.url
            origin = origin_of(current)

            if origin == self.settings.host_origin:
                if await self.is_login_page(page):
                    sign_ins += 1
                    if sign_ins > MAX_SIGN_INS_PER_VISIT:
                        raise ModuleFailure(f"the login page came back after {MAX_SIGN_INS_PER_VISIT} sign-ins: "
                                            f"the server under test does not accept LOGIN_EMAIL and LOGIN_PASSWORD")
                    # Taken before the form is filled: the logo, policy, terms and second-login modules want this page
                    last_server_page = await self.capture(page, "login page")
                    await self.sign_in(page)
                    continue
                if await page.locator("#sign-out").count() > 0:
                    log(self.scope, "click", f"sign-out on {current}")
                    await page.locator("#sign-out").first.click()
                    continue
                # A page of the server under test that neither asks to sign in nor to confirm a logout and does not
                # move on: an error page or a logged-out page, the one a module expecting a screenshot wants
                last_server_page = await self.capture(page, "server page")
                log(self.scope, "stop", f"server page '{await page.title()}' at {current}")
                return VisitResult(last_server_page)

            if origin == self.settings.suite_origin:
                await self.finish_on_suite(page)
                return VisitResult(last_server_page)

            raise ModuleFailure(f"the browser reached {current}, neither the suite nor the server under test")

        raise ModuleFailure(f"no stable page after {MAX_STEPS_PER_VISIT} steps, last at {page.url}")

    async def settle(self, page: Page) -> None:
        """Waits until the page stops loading and its address holds still: auto-submitting forms move on by then."""
        deadline = time.monotonic() + self.settings.page_timeout_ms / 1000
        while True:
            await page.wait_for_load_state("load")
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightTimeoutError:
                pass  # a page polling the network never idles; the address check below still decides
            before = page.url
            await page.wait_for_timeout(self.settings.settle_ms)
            if page.url == before:
                return
            if time.monotonic() > deadline:
                raise ModuleFailure(f"the page kept navigating for {self.settings.page_timeout_ms / 1000:.0f}s, "
                                    f"last at {page.url}")

    @staticmethod
    async def is_login_page(page: Page) -> bool:
        return (await page.locator("input[name='email']").count() > 0
                and await page.locator("input[name='password']").count() > 0)

    async def sign_in(self, page: Page) -> None:
        log(self.scope, "sign-in", f"as {self.settings.login_email} on {page.url}")
        await page.locator("input[name='email']").first.fill(self.settings.login_email)
        await page.locator("input[name='password']").first.fill(self.settings.login_password)
        submit = page.locator("#sign-in")
        if await submit.count() == 0:
            submit = page.locator("form button[type='submit'], form input[type='submit']")
        if await submit.count() == 0:
            raise ModuleFailure(f"the login page at {page.url} has no submit button")
        await submit.first.click()

    async def finish_on_suite(self, page: Page) -> None:
        current = page.url
        path = urlsplit(current).path
        if re.search(r"/test/.+/callback", path):
            # implicitCallback.html posts the response back to the module, then adds this element
            try:
                await page.locator(SUBMISSION_COMPLETE_SELECTOR).wait_for(state="attached")
            except PlaywrightTimeoutError:
                raise ModuleFailure(f"the suite callback page at {current} never reported its submission complete") from None
            log(self.scope, "done", f"suite callback submitted at {current}")
            return
        if "session_verify" in current:
            # The suite's page reads the session through the server's check_session_iframe and navigates on
            try:
                await page.wait_for_url(re.compile("session_result"))
            except PlaywrightTimeoutError:
                raise ModuleFailure(f"the session check page at {current} never reported a session_result") from None
            log(self.scope, "done", f"session check reported at {page.url}")
            return
        log(self.scope, "done", f"back on the suite at {current}")

    async def capture(self, page: Page, kind: str) -> Screenshot:
        attempts = [
            {"full_page": True, "type": "png"},
            {"full_page": True, "type": "jpeg", "quality": 80},
            {"full_page": True, "type": "jpeg", "quality": 60},
            {"full_page": True, "type": "jpeg", "quality": 40},
            {"full_page": False, "type": "jpeg", "quality": 40},
        ]
        facts = PageFacts(
            login_form=await self.is_login_page(page),
            client_logo=await self.attribute_of(page, "#client-logo", "src"),
            client_policy=await self.attribute_of(page, "#client-policy", "href"),
            client_terms=await self.attribute_of(page, "#client-tos", "href"),
        )
        for options in attempts:
            image = await page.screenshot(**options)
            if len(image) <= UPLOAD_SIZE_LIMIT:
                mime = "image/png" if options["type"] == "png" else "image/jpeg"
                shot = Screenshot(
                    f"data:{mime};base64,{base64.b64encode(image).decode('ascii')}", len(image), page.url, kind, facts)
                log(self.scope, "screenshot", f"{kind}, {len(image)} bytes {mime}, of {page.url}")
                self.save_copy(image, options["type"])
                return shot
        raise ModuleFailure(f"no screenshot of {page.url} fits the suite's {UPLOAD_SIZE_LIMIT} byte upload limit")

    @staticmethod
    async def attribute_of(page: Page, selector: str, attribute: str) -> str | None:
        element = page.locator(selector)
        if await element.count() == 0:
            return None
        return await element.first.get_attribute(attribute)

    def save_copy(self, image: bytes, extension: str) -> None:
        if not self.settings.screenshot_dir:
            return
        os.makedirs(self.settings.screenshot_dir, exist_ok=True)
        name = f"{self.test_id}-{int(time.time() * 1000)}.{extension}"
        with open(os.path.join(self.settings.screenshot_dir, name), "wb") as file:
            file.write(image)

    async def upload_screenshot(self) -> None:
        remaining = [str(entry["upload"]) for entry in await self.api.list_images(self.test_id) if "upload" in entry]
        remaining = [placeholder for placeholder in remaining if placeholder not in self.filled_placeholders]
        if not remaining:
            return
        if len(remaining) > 1:
            raise ModuleFailure(f"the module waits on {len(remaining)} placeholders ({', '.join(remaining)}); "
                                f"the driver cannot tell which page belongs to which")
        shot = self.last_visit.last_server_page if self.last_visit else None
        if shot is None:
            raise ModuleFailure("the module waits for a screenshot, but its last visit showed no page of the "
                                "server under test")
        expectation = expectation_for(self.module_name)
        if expectation is None:
            raise ModuleFailure(f"the module waits for a screenshot, and the driver knows no check of what its page "
                                f"has to show; add one to expectation_for")
        description, holds = expectation
        if not holds(shot):
            raise ModuleFailure(f"the page captured for review should show {description}, "
                                f"but {shot.page_url} shows {shot.facts}")
        log(self.scope, "check", f"the page shows {description}")
        placeholder = remaining[0]
        await self.api.fill_placeholder(self.test_id, placeholder, shot.data_uri)
        self.filled_placeholders.add(placeholder)
        log(self.scope, "upload", f"{shot.kind} of {shot.page_url} to placeholder {placeholder}, {shot.size} bytes")


class Driver:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.tasks: dict[str, asyncio.Task] = {}
        self.failures: list[str] = []
        self.stop_requested = asyncio.Event()
        # Modules the suite already held when the driver started belong to an earlier run: a suite left running keeps
        # its waiting modules forever, and driving them would report that run's leftovers as this one's failures
        self.earlier: set[str] = set()

    async def run(self) -> int:
        settings = self.settings
        log("driver", "start", f"suite {settings.suite_url}, server under test {settings.host_origin}, "
                               f"deadline {settings.deadline_seconds:.0f}s")
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, self.stop_requested.set)

        deadline = time.monotonic() + settings.deadline_seconds
        api = SuiteApi(settings)
        deadline_hit = False
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                log("driver", "browser", f"chromium {browser.version}")
                self.earlier = set(await api.list_running_test_ids())
                log("driver", "earlier", f"{len(self.earlier)} module(s) left by an earlier run, not driven")
                try:
                    while not self.stop_requested.is_set():
                        if time.monotonic() > deadline:
                            deadline_hit = True
                            break
                        await self.start_new_modules(api, browser)
                        try:
                            await asyncio.wait_for(self.stop_requested.wait(), timeout=settings.poll_seconds)
                        except asyncio.TimeoutError:
                            pass
                finally:
                    await self.cancel_unfinished()
                    await browser.close()
        finally:
            await api.close()

        if deadline_hit:
            log("driver", "FAIL", f"deadline of {settings.deadline_seconds:.0f}s reached while the suite was still "
                                  f"running modules; nobody stopped the driver")
            self.failures.append("deadline reached")
        for failure in self.failures:
            log("driver", "summary", f"failed: {failure}")
        log("driver", "exit", f"{len(self.tasks)} module(s) seen, {len(self.failures)} failure(s)")
        return 1 if self.failures else 0

    async def start_new_modules(self, api: SuiteApi, browser: Browser) -> None:
        try:
            running = await api.list_running_test_ids()
        except (ModuleFailure, httpx.HTTPError) as error:
            # The suite is shared with the runner, which waits for it to come back after a restart; so does this
            log("driver", "suite-unreachable", str(error))
            return
        for test_id in running:
            if test_id not in self.tasks and test_id not in self.earlier:
                module = ModuleDriver(test_id, self.settings, api, browser)
                self.tasks[test_id] = asyncio.create_task(self.drive(module))

    async def drive(self, module: ModuleDriver) -> None:
        try:
            await module.run()
        except ModuleFailure as failure:
            log(module.scope, "FAIL", str(failure))
            self.failures.append(f"{module.scope}: {failure}")
        except httpx.HTTPError as error:
            log(module.scope, "FAIL", f"suite API unreachable: {error}")
            self.failures.append(f"{module.scope}: suite API unreachable: {error}")

    async def cancel_unfinished(self) -> None:
        for test_id, task in self.tasks.items():
            if not task.done():
                log("driver", "cancel", f"module {test_id} still in progress at shutdown")
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)


def main() -> int:
    settings = Settings.from_environment()
    return asyncio.run(Driver(settings).run())


if __name__ == "__main__":
    sys.exit(main())
