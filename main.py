from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone
from urllib.parse import urljoin
import os
import json
import logging
import atexit
import time
import gc
import threading
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
from supabase import create_client
try:
    import resend as _resend
    _resend_available = True
except ImportError:
    _resend_available = False

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

SUPABASE_URL     = "https://ktkwtlrnrzrnigevvccc.supabase.co"
SUPABASE_KEY     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt0a3d0bHJucnpybmlnZXZ2Y2NjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcyNTQ5NDIsImV4cCI6MjA5MjgzMDk0Mn0.RuKhrCpfa-kl16dQ1FBdi6v3crZUPcyB-xPDkW7nmYo"
SUPABASE_SERVICE = os.environ.get('SUPABASE_SERVICE_KEY', '')

_auth   = create_client(SUPABASE_URL, SUPABASE_KEY)
_admin  = create_client(SUPABASE_URL, SUPABASE_SERVICE) if SUPABASE_SERVICE else None

RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
if _resend_available and RESEND_API_KEY:
    _resend.api_key = RESEND_API_KEY

def user_db(token: str):
    """Per-request client scoped to a user's JWT — satisfies RLS without mutating global state."""
    c = create_client(SUPABASE_URL, SUPABASE_KEY)
    c.postgrest.auth(token)
    return c

app = Flask(__name__, static_folder='static')
CORS(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)

Talisman(app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': [
            "'self'", "'unsafe-inline'",
            'https://cdnjs.cloudflare.com',
            'https://unpkg.com',
            'https://cdn.jsdelivr.net',
        ],
        'script-src-elem': [
            "'self'", "'unsafe-inline'",
            'https://cdnjs.cloudflare.com',
            'https://unpkg.com',
            'https://cdn.jsdelivr.net',
        ],
        'style-src': ["'self'", "'unsafe-inline'", 'fonts.googleapis.com'],
        'font-src': ["'self'", 'fonts.gstatic.com'],
        'img-src': ["'self'", 'data:'],
        'connect-src': [
            "'self'",
            'https://*.supabase.co',
            'https://unpkg.com',
            'https://cdnjs.cloudflare.com',
            'https://cdn.jsdelivr.net',
        ],
        'worker-src': ["'self'", 'blob:'],
    }
)

# ── Encryption ─────────────────────────────────────────────────────────────────
# Generate a key once:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Then set CREDENTIAL_KEY=<that value> in your environment / Replit secrets.
_raw_key = os.environ.get('CREDENTIAL_KEY')
if not _raw_key:
    log.warning("CREDENTIAL_KEY not set — generating ephemeral key. Stored IC credentials will break on restart.")
    _raw_key = Fernet.generate_key().decode()

fernet = Fernet(_raw_key.encode() if isinstance(_raw_key, str) else _raw_key)

def encrypt_val(s: str) -> str:
    return fernet.encrypt(s.encode()).decode()

def decrypt_val(s: str) -> str:
    return fernet.decrypt(s.encode()).decode()

# ── Auth helper ────────────────────────────────────────────────────────────────
def get_uid(auth_header: str) -> str:
    token = auth_header.replace('Bearer ', '').strip()
    user = _auth.auth.get_user(token)
    return user.user.id

# ── Input validation ───────────────────────────────────────────────────────────
def _validate_ic_domain(domain: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,100}\.[a-zA-Z]{2,}$', domain))

def _validate_username(username: str) -> bool:
    return bool(username) and len(username) <= 100 and bool(re.match(r'^[\w\.\-@\s]+$', username))

# ── NCEDCloud + Infinite Campus ────────────────────────────────────────────────
NCEDCLOUD_BASE = 'https://ncedcloud.mcnc.org'
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)

def _make_session() -> requests.Session:
    sess = requests.Session()
    sess.headers['User-Agent'] = USER_AGENT
    return sess

def playwright_ic_sync(username: str, password: str, ic_domain: str) -> list:
    """
    NCEDCloud -> Infinite Campus SSO + grade fetch, all via one Playwright session.
    Fetches grades while the browser is still open — avoids cookie transfer issues
    (IC ties sessions to browser fingerprint server-side).
    Returns list of course dicts. Raises ValueError on bad credentials.
    """
    import re as _re
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    # ── Step 1: Find SSO URL via requests (fast, no browser needed) ───────────
    try:
        r = requests.get(f'https://{ic_domain}/campus/', timeout=15,
                         allow_redirects=True, headers={'User-Agent': USER_AGENT})
        r.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f'Could not reach IC domain {ic_domain}: {e}')

    soup = BeautifulSoup(r.text, 'html.parser')
    sso_url = None
    app_match = _re.search(r'/campus/([^/]+?)(?:\.jsp)?(?:\?|$)', r.url)
    appname = app_match.group(1) if app_match else None

    sel = soup.find('select', {'id': _re.compile(r'saml.*select', _re.I)}) or \
          soup.find('select', {'name': _re.compile(r'saml|sso|config', _re.I)})
    if sel:
        for opt in sel.find_all('option'):
            if 'ncedcloud' in opt.get_text(strip=True).lower():
                val = opt.get('value', '').strip()
                if val.startswith('http'):
                    sso_url = val
                elif val.startswith('/'):
                    sso_url = urljoin(f'https://{ic_domain}', val)
                elif val and appname:
                    sso_url = f'https://{ic_domain}/campus/SSO/{appname}/sis?configID={val}'
                break

    if not sso_url:
        for a in soup.find_all('a', href=True):
            if 'ncedcloud' in (a.get_text(strip=True) + a['href']).lower():
                sso_url = urljoin(r.url, a['href']); break

    if not sso_url and appname:
        sso_url = f'https://{ic_domain}/campus/SSO/{appname}/sis?configID=1'

    if not sso_url:
        raise RuntimeError(f'Could not find NCEDCloud SSO option on {ic_domain}.')

    log.info(f'NCEdCloud SSO URL: {sso_url}')

    # ── Step 2: Playwright handles the JS-driven SAML SSO flow ───────────────
    log.info('Playwright: starting browser launch...')
    with sync_playwright() as p:
        log.info('Playwright: sync_playwright context entered')
        browser = p.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--single-process',
                '--disable-extensions',
                '--disable-background-networking',
                '--disable-images',
                '--blink-settings=imagesEnabled=false',
                '--js-flags=--max-old-space-size=96',
                '--disk-cache-size=1',
                '--media-cache-size=1',
            ]
        )
        log.info('Playwright: browser launched')
        context = browser.new_context(user_agent=USER_AGENT)
        context.set_default_timeout(60000)
        page = context.new_page()

        # ── Intercept ALL JSON API responses from the very start ──────────────
        grade_data_map = {}

        def _capture_json(response):
            if response.status != 200:
                return
            ct = response.headers.get('content-type', '')
            if 'json' not in ct:
                return
            try:
                body = response.json()
                grade_data_map[response.url] = body
                log.info(f'IC intercepted: {response.url}')
            except BaseException:
                pass

        page.on('response', _capture_json)

        try:
            page.goto(sso_url, wait_until='load', timeout=60000)
            log.info(f'Playwright: landed on {page.url}')

            if 'idp.ncedcloud.org' not in page.url:
                raise RuntimeError(f'Expected NCEDCloud IDP, got {page.url}')

            page.wait_for_selector('input:visible')
            page.locator('input:visible').first.fill(username)
            log.info('Playwright: username filled')

            try:
                page.locator('button:visible').first.click()
            except Exception:
                page.keyboard.press('Enter')

            page.wait_for_selector('input[type="password"]')
            page.fill('input[type="password"]', password)
            log.info('Playwright: password filled')

            try:
                page.locator('button:visible').first.click()
            except Exception:
                page.keyboard.press('Enter')
            log.info(f'Playwright: password submitted, current url={page.url}')

            try:
                page.wait_for_url(
                    lambda url: 'idp.ncedcloud.org' not in url,
                    timeout=90000
                )
                log.info(f'Playwright: left NCEDCloud IDP, now at {page.url}')
                try:
                    page.wait_for_load_state('networkidle', timeout=15000)
                except Exception:
                    pass
                log.info(f'Playwright: settled at {page.url}')
                if ic_domain not in page.url:
                    body_text = page.inner_text('body')
                    if any(w in body_text.lower() for w in ('invalid', 'incorrect', 'failed', 'denied')):
                        raise ValueError('Invalid NCEDCloud username or password.')
                    raise RuntimeError(
                        f'SSO did not land on IC domain. Ended at: {page.url}'
                    )
                log.info(f'Playwright: IC session established at {page.url}')
            except PWTimeout:
                body_text = page.inner_text('body')
                if any(w in body_text.lower() for w in ('invalid', 'incorrect', 'failed', 'denied')):
                    raise ValueError('Invalid NCEDCloud username or password.')
                raise RuntimeError('NCEDCloud SSO timed out — may still be on IDP after 90s.')

            # ── Fetch grades from confirmed endpoints ─────────────────────────
            base = f'https://{ic_domain}'
            courses = []

            try:
                page.goto(f'{base}/campus/resources/portal/grades',
                          wait_until='domcontentloaded', timeout=60000)
                raw = page.inner_text('body').strip()
                log.info(f'IC grades body[:2000]={raw[:2000]}')
                courses = _normalize_ic_api(json.loads(raw), None)
                log.info(f'IC grades: {len(courses)} courses')
            except Exception as e:
                log.info(f'IC grades endpoint failed: {e}')

            for c in courses:
                sid = c.get('section_id')
                if not sid:
                    c['categories_by_term'] = {}
                    c['assignments'] = []
                    continue
                try:
                    url = (f'{base}/campus/resources/portal/grades/detail/{sid}'
                           f'?showAllTerms=true&classroomSectionID={sid}')
                    detail = page.evaluate(f'''
                        async () => {{
                            const r = await fetch("{url}");
                            if (!r.ok) return {{}};
                            return r.json();
                        }}
                    ''')
                    cats_by_term = {}
                    all_asgns    = []
                    for d in detail.get('details', []):
                        term_name = _normalize_term(d.get('task', {}).get('termName', 'Unknown'))
                        cats = []
                        for cat in d.get('categories', []):
                            asgns = []
                            for a in cat.get('assignments', []):
                                asgn = {
                                    'name':       a.get('assignmentName', ''),
                                    'due':        a.get('dueDate', ''),
                                    'score':      a.get('scorePoints'),
                                    'max':        a.get('totalPoints'),
                                    'pct':        a.get('scorePercentage'),
                                    'missing':    a.get('missing', False),
                                    'late':       a.get('late', False),
                                    'dropped':    a.get('dropped', False),
                                    'incomplete': a.get('incomplete', False),
                                    'notGraded':  a.get('notGraded', False),
                                    'category':   cat.get('name', ''),
                                }
                                asgns.append(asgn)
                                all_asgns.append(asgn)
                            cats.append({
                                'name':        cat.get('name', 'Other'),
                                'weight':      cat.get('weight', 0),
                                'assignments': asgns,
                            })
                        if len(cats) > len(cats_by_term.get(term_name, [])):
                            cats_by_term[term_name] = cats
                    c['categories_by_term'] = cats_by_term
                    c['assignments']         = all_asgns
                    log.info(f'IC detail section={sid}: {len(cats_by_term)} terms, {len(all_asgns)} assignments')
                except Exception as e:
                    log.info(f'IC detail fetch failed section={sid}: {e}')
                    c['categories_by_term'] = {}
                    c['assignments']         = []

            log.info(f'IC Playwright pull complete: {len(courses)} courses')
            return courses

        except (ValueError, RuntimeError):
            raise
        except Exception as e:
            raise RuntimeError(f'NCEDCloud SSO error: {e}')
        finally:
            try:
                context.close()
            except Exception:
                pass
            browser.close()


def _follow_saml(sess: requests.Session, soup: BeautifulSoup) -> bool:
    """If the page contains a SAML auto-submit form, POST it. Returns True if posted."""
    for form in soup.find_all('form'):
        saml_inp = form.find('input', {'name': 'SAMLResponse'})
        if saml_inp:
            saml_payload = {
                inp['name']: inp.get('value', '')
                for inp in form.find_all('input')
                if inp.get('name')
            }
            saml_action = form.get('action', '')
            log.info(f'SAML form found -> POST {saml_action} payload_keys={list(saml_payload.keys())}')
            if saml_action:
                try:
                    r = sess.post(saml_action, data=saml_payload, timeout=15, allow_redirects=True)
                    log.info(f'SAML POST -> {r.status_code} final_url={r.url}')
                    return True
                except requests.RequestException as e:
                    log.warning(f'SAML POST failed: {e}')
    log.info('_follow_saml: no SAMLResponse form found on this page')
    return False


def ic_pull_grades(sess: requests.Session, ic_domain: str) -> list:
    """
    Fetch current course grades + assignments from IC.
    Tries REST API first, falls back to HTML scraping.
    Returns list of dicts: [{name, grade, letter, term, source, assignments:[]}]
    """
    base = f'https://{ic_domain}'
    courses = []

    person_id = None
    for path in ['/campus/api/portal/students', '/campus/api/portal/student']:
        try:
            r = sess.get(f'{base}{path}', timeout=10)
            log.info(f'IC students endpoint {path} -> {r.status_code}')
            if r.status_code == 200:
                d = r.json()
                if isinstance(d, list):
                    d = d[0] if d else {}
                person_id = (d.get('personID') or d.get('id') or
                             d.get('studentID') or d.get('student', {}).get('personID'))
                log.info(f'IC students response keys: {list(d.keys()) if isinstance(d, dict) else "not a dict"}')
                if person_id:
                    break
        except Exception as e:
            log.info(f'IC students {path} error: {e}')

    if person_id:
        for path in [
            f'/campus/api/portal/students/{person_id}/grades',
            f'/campus/api/portal/grades?personID={person_id}',
            f'/campus/api/portal/students/{person_id}/roster?_expand=%7Bsection%7D',
            f'/campus/api/portal/students/{person_id}/term',
            f'/campus/api/portal/students/{person_id}/schoolYears',
        ]:
            try:
                r = sess.get(f'{base}{path}', timeout=10)
                log.info(f'IC grades {path} -> {r.status_code} len={len(r.text)}')
                if r.status_code == 200 and r.text.strip():
                    log.info(f'IC grades {path} body[:400]={r.text[:400]}')
                    courses = _normalize_ic_api(r.json(), person_id)
                    if courses:
                        break
            except Exception as e:
                log.info(f'IC grades {path} error: {e}')

    if not courses:
        for path in ['/campus/api/portal/grades', '/campus/api/portal/students/courses']:
            try:
                r = sess.get(f'{base}{path}', timeout=10)
                log.info(f'IC generic {path} -> {r.status_code} len={len(r.text)}')
                if r.status_code == 200 and r.text.strip():
                    courses = _normalize_ic_api(r.json(), person_id)
                    if courses:
                        break
            except Exception as e:
                log.info(f'IC generic {path} error: {e}')

    if not courses:
        try:
            r = sess.get(f'{base}/campus/prism', params={'x': 'portal.PortalGrades'}, timeout=10)
            log.info(f'IC HTML prism -> {r.status_code} len={len(r.text)} body[:300]={r.text[:300]}')
            if r.status_code == 200:
                courses = _parse_ic_html(r.text)
                log.info(f'IC HTML parse -> {len(courses)} courses')
        except Exception as e:
            log.info(f'IC HTML error: {e}')

    if not courses:
        try:
            r = sess.get(f'{base}/campus/portal/grades.jsp', timeout=10)
            log.info(f'IC grades.jsp -> {r.status_code} len={len(r.text)}')
            if r.status_code == 200:
                courses = _parse_ic_html(r.text)
        except Exception as e:
            log.info(f'IC grades.jsp error: {e}')

    if courses and person_id:
        for c in courses:
            c['assignments'] = _fetch_ic_assignments(sess, base, person_id, c)
    elif courses:
        for c in courses:
            c.setdefault('assignments', [])

    log.info(f'IC pull complete: {len(courses)} courses')
    return courses


def _fetch_ic_assignments(sess, base, person_id, course):
    """Fetch assignment-level data for a single IC course."""
    assignments = []
    section_id = course.get('section_id') or course.get('sectionID')

    if section_id:
        try:
            r = sess.get(
                f'{base}/campus/api/portal/students/{person_id}/grades/{section_id}/assignments',
                timeout=10
            )
            if r.status_code == 200:
                raw = r.json()
                items = raw if isinstance(raw, list) else raw.get('assignments', [])
                for a in items:
                    assignments.append({
                        'name':     a.get('assignmentName') or a.get('name', 'Unknown'),
                        'category': a.get('categoryName') or a.get('category', ''),
                        'score':    a.get('score'),
                        'max':      a.get('totalPoints') or a.get('maxScore') or a.get('pointsPossible'),
                        'percent':  a.get('percent'),
                        'due':      a.get('dueDate') or a.get('due'),
                    })
        except Exception:
            pass

    return assignments


def _normalize_term(raw: str) -> str:
    """Normalize IC termName variants to Q1/Q2/Q3/Q4/Final."""
    if not raw:
        return raw
    raw = raw.strip()
    m = re.search(r'Q([1-4])', raw, re.IGNORECASE)
    if m:
        return f'Q{m.group(1)}'
    if re.search(r'final|exam', raw, re.IGNORECASE):
        return 'Final'
    return raw


def _normalize_ic_api(data, person_id=None) -> list:
    """
    Normalise IC /campus/resources/portal/grades response into Slate's grade format.
    Structure: [{enrollmentID, terms:[{termName, courses:[{courseName, ...grade fields}]}]}]
    """
    courses = []

    enrollments = data if isinstance(data, list) else [data]
    flat_courses = []
    today = datetime.now(timezone.utc).date()

    for enrollment in enrollments:
        if not isinstance(enrollment, dict):
            continue
        for term in enrollment.get('terms', []):
            term_name  = term.get('termName') or term.get('term', '')
            term_start = term.get('startDate', '')
            term_end   = term.get('endDate', '')
            for course in term.get('courses', []):
                flat_courses.append((term_name, term_start, term_end, course))

    if not flat_courses:
        items = data if isinstance(data, list) else data.get('courses', [])
        flat_courses = [(c.get('termName', ''), '', '', c) for c in items if isinstance(c, dict)]

    for term_name, term_start, term_end, item in flat_courses:
        try:
            name = (item.get('courseName') or item.get('name') or
                    item.get('courseTitle') or 'Unknown Course')

            grading_tasks = item.get('gradingTasks') or []
            task = next(
                (t for t in grading_tasks if t.get('portal') and t.get('taskName') == 'Term Grade'),
                next((t for t in grading_tasks if t.get('portal')), None) or
                (grading_tasks[0] if grading_tasks else None)
            )

            if not task:
                log.info(f'IC skip {name}: no gradingTask (tasks={len(grading_tasks)})')
                continue

            pct = task.get('percent') or task.get('progressPercent')
            score_str = task.get('score') or task.get('progressScore')
            task_term = _normalize_term(task.get('termName') or term_name)

            log.info(f'IC course {name} | term={task_term} | pct={pct} | score={score_str} | portal={task.get("portal")}')

            if pct is None:
                log.info(f'IC skip {name}: pct is None, task keys={list(task.keys())}')
                continue

            courses.append({
                'name':       str(name).strip(),
                'grade':      float(pct),
                'letter':     str(score_str).strip() if score_str else None,
                'term':       str(task_term).strip(),
                'term_start': term_start,
                'term_end':   term_end,
                'source':     'ic',
                'section_id': item.get('sectionID') or item.get('sectionId'),
            })
        except Exception:
            continue

    return courses


def _parse_ic_html(html: str) -> list:
    """Fallback: parse IC's PortalGrades HTML page into grade records."""
    soup = BeautifulSoup(html, 'html.parser')
    courses = []

    for row in soup.select('tr.courseRow, tr[class*="course"], .gradeRow'):
        try:
            cells = row.find_all('td')
            if len(cells) < 2:
                continue
            name = cells[0].get_text(strip=True)
            grade_text = cells[-1].get_text(strip=True).replace('%', '').strip()
            pct = float(grade_text)
            courses.append({'name': name, 'grade': pct, 'letter': None, 'term': '', 'source': 'ic'})
        except (ValueError, IndexError):
            continue

    return courses


# ── Background sync ────────────────────────────────────────────────────────────
def _grade_snapshot(grades: list) -> dict:
    """Build a {(name, term): grade} map for change detection."""
    return {(c.get('name', ''), c.get('term', '')): c.get('grade') for c in (grades or [])}


_Q_ORDER = ['Q1', 'Q2', 'Q3', 'Q4']

def _past_quarter_set() -> set:
    """Return the set of quarter labels that are fully finished as of today."""
    cq = get_quarter()
    if cq == 'all':
        return set()
    try:
        idx = _Q_ORDER.index(cq)
        return set(_Q_ORDER[:idx])
    except ValueError:
        return set()


def sync_user_ic(uid: str, ic_domain: str, ic_username: str, encrypted_pw: str, token: str = None):
    """Re-auth and refresh IC grades for a single user. Returns grades list on success, None on failure."""
    try:
        db = user_db(token) if token else (_admin or _auth)
        now = datetime.now(timezone.utc)
        past_qs = _past_quarter_set()

        old_grades      = []
        ic_past_synced  = None
        try:
            old_row = db.table('users').select('ic_grades_cache, ic_past_synced_at').eq('id', uid).execute()
            if old_row.data:
                old_grades     = old_row.data[0].get('ic_grades_cache') or []
                ic_past_synced = old_row.data[0].get('ic_past_synced_at')
        except Exception:
            pass

        # Past grades are stale if never fetched or older than 7 days
        past_stale = True
        if ic_past_synced:
            try:
                last = datetime.fromisoformat(ic_past_synced.replace('Z', '+00:00'))
                past_stale = (now - last).days >= 7
            except Exception:
                pass

        cached_past = [g for g in old_grades if g.get('term') in past_qs] if (not past_stale and past_qs) else []

        password = decrypt_val(encrypted_pw)
        if not _playwright_lock.acquire(timeout=180):
            log.warning(f'Playwright lock timeout for user {uid[:8]}...')
            return None
        try:
            grades = playwright_ic_sync(ic_username, password, ic_domain)
        finally:
            _playwright_lock.release()

        if cached_past:
            # Drop past-quarter entries from fresh IC data, substitute cached ones
            current_grades = [g for g in grades if g.get('term') not in past_qs]
            grades = current_grades + cached_past
            db_update = {'ic_grades_cache': grades, 'ic_synced_at': now.isoformat()}
            log.info(f'IC sync OK for {uid[:8]}... ({len(grades)} courses, past quarters from cache)')
        else:
            db_update = {
                'ic_grades_cache':   grades,
                'ic_synced_at':      now.isoformat(),
                'ic_past_synced_at': now.isoformat(),
            }
            log.info(f'IC sync OK for {uid[:8]}... ({len(grades)} courses, past quarters refreshed)')

        db.table('users').update(db_update).eq('id', uid).execute()
        send_grade_email(uid, len(grades))
        return grades
    except Exception as e:
        log.warning(f'IC sync failed for user {uid[:8]}...: {e}')
        return None


_sync_running = False
_playwright_lock = threading.Lock()

def sync_all_ic_users():
    """Scheduled job — runs every 20 minutes, refreshes grades for all IC-connected users."""
    global _sync_running
    if _sync_running:
        log.info('IC sync job: previous run still in progress, skipping')
        return
    if not _admin:
        log.warning('IC sync job: SUPABASE_SERVICE_KEY not set, skipping')
        return
    _sync_running = True
    try:
        rows = (
            _admin.table('users')
            .select('id, ic_domain, ic_username, ic_password')
            .not_.is_('ic_domain', 'null')
            .not_.is_('ic_password', 'null')
            .execute()
            .data
        )
        log.info(f'IC sync job: {len(rows)} users to refresh')
        for row in rows:
            sync_user_ic(row['id'], row['ic_domain'], row['ic_username'], row['ic_password'])
            gc.collect()
            time.sleep(20)
    except Exception as e:
        log.error(f'IC sync job error: {e}')
    finally:
        _sync_running = False


scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(sync_all_ic_users, 'interval', minutes=20, id='ic_sync', replace_existing=True, max_instances=1, coalesce=True)
scheduler.start()
atexit.register(lambda: scheduler.shutdown(wait=False))


# ── Email notifications ────────────────────────────────────────────────────────
def send_grade_email(uid: str, course_count: int):
    """Email the user after a successful IC sync. No-ops if Resend isn't configured."""
    if not (_resend_available and RESEND_API_KEY and _admin):
        return
    try:
        user = _admin.auth.admin.get_user_by_id(uid)
        email = user.user.email if user and user.user else None
        if not email:
            return
        _resend.Emails.send({
            'from': 'onboarding@resend.dev',
            'to': email,
            'subject': 'Slate — Grades Updated',
            'html': (
                f'<p>Your grades were just synced.</p>'
                f'<p><strong>{course_count} courses</strong> updated.</p>'
                f'<p><a href="https://slatet.onrender.com">Open Slate</a></p>'
            ),
        })
    except Exception as e:
        log.warning(f'Email failed for {uid[:8]}...: {e}')


# ── IC API endpoints ───────────────────────────────────────────────────────────
@app.route('/api/connect_ic', methods=['POST'])
@limiter.limit("3 per minute")
def connect_ic():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    data = request.json or {}

    ic_domain  = data.get('ic_domain', '').replace('https://', '').replace('http://', '').rstrip('/')
    username   = data.get('username', '').strip()
    password   = data.get('password', '').strip()

    if not ic_domain or not username or not password:
        return jsonify({'error': 'IC domain, NCEDCloud username, and password are required.'}), 400

    if not _validate_ic_domain(ic_domain):
        return jsonify({'error': 'Invalid IC domain format.'}), 400

    if not _validate_username(username):
        return jsonify({'error': 'Invalid username format.'}), 400

    try:
        uid = get_uid(auth_header)
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        grades = playwright_ic_sync(username, password, ic_domain)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {e}'}), 500

    now_iso = datetime.now(timezone.utc).isoformat()

    user_db(token).table('users').update({
        'ic_domain':       ic_domain,
        'ic_username':     username,
        'ic_password':     encrypt_val(password),
        'ic_enabled':      True,
        'ic_grades_cache': grades,
        'ic_synced_at':    now_iso,
    }).eq('id', uid).execute()

    return jsonify({'ok': True, 'grades': grades, 'synced_at': now_iso, 'course_count': len(grades)})


@app.route('/api/disconnect_ic', methods=['POST'])
def disconnect_ic():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    try:
        uid = get_uid(auth_header)
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401

    user_db(token).table('users').update({
        'ic_domain':       None,
        'ic_username':     None,
        'ic_password':     None,
        'ic_enabled':      False,
        'ic_grades_cache': None,
        'ic_synced_at':    None,
    }).eq('id', uid).execute()

    return jsonify({'ok': True})


@app.route('/api/toggle_ic', methods=['POST'])
def toggle_ic():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    data = request.json or {}
    enabled = bool(data.get('enabled', False))

    try:
        uid = get_uid(auth_header)
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401

    user_db(token).table('users').update({'ic_enabled': enabled}).eq('id', uid).execute()
    return jsonify({'ok': True, 'enabled': enabled})


@app.route('/api/sync_ic', methods=['POST'])
@limiter.limit("5 per minute")
def sync_ic_now():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    try:
        uid = get_uid(auth_header)
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401

    res = user_db(token).table('users').select('ic_domain, ic_username, ic_password').eq('id', uid).execute()
    if not res.data or not res.data[0].get('ic_domain') or not res.data[0].get('ic_password'):
        return jsonify({'error': 'reconnect', 'message': 'IC credentials missing — re-enter them in Settings.'}), 400
    row = res.data[0]

    try:
        decrypt_val(row['ic_password'])
    except Exception:
        return jsonify({'error': 'reconnect', 'message': 'Stored IC credentials are invalid (server key changed). Re-enter your password in Settings.'}), 400

    grades = sync_user_ic(uid, row['ic_domain'], row['ic_username'], row['ic_password'], token=token)
    if grades is None:
        return jsonify({'error': 'Sync failed — check credentials or IC domain'}), 400

    now_iso = datetime.now(timezone.utc).isoformat()
    return jsonify({'ok': True, 'grades': grades, 'synced_at': now_iso})


@app.route('/api/ic_status', methods=['GET'])
def ic_status():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '').strip()
    try:
        uid = get_uid(auth_header)
    except Exception:
        return jsonify({'error': 'Unauthorized'}), 401

    res = (
        user_db(token).table('users')
        .select('ic_domain, ic_enabled, ic_grades_cache, ic_synced_at')
        .eq('id', uid)
        .execute()
    )

    if not res.data:
        return jsonify({'connected': False, 'enabled': False})

    row = res.data[0]
    connected = bool(row.get('ic_domain'))

    return jsonify({
        'connected':  connected,
        'enabled':    bool(row.get('ic_enabled')) and connected,
        'domain':     row.get('ic_domain'),
        'grades':     row.get('ic_grades_cache') or [],
        'synced_at':  row.get('ic_synced_at'),
    })


# ── Existing Canvas auth ───────────────────────────────────────────────────────
@app.route("/api/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
    data = request.json
    try:
        res = _auth.auth.sign_up({"email": data["email"], "password": data["password"]})
        return jsonify({"ok": True, "user": res.user.id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/login_user", methods=["POST"])
@limiter.limit("10 per minute")
def login_user():
    data = request.json
    try:
        res = _auth.auth.sign_in_with_password({"email": data["email"], "password": data["password"]})
        return jsonify({"ok": True, "token": res.session.access_token, "refresh_token": res.session.refresh_token})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/refresh_token", methods=["POST"])
def refresh_token():
    data = request.json or {}
    rt = data.get("refresh_token", "")
    if not rt:
        return jsonify({"error": "missing refresh_token"}), 400
    try:
        res = _auth.auth.refresh_session(rt)
        return jsonify({"ok": True, "token": res.session.access_token, "refresh_token": res.session.refresh_token})
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/api/save_canvas", methods=["POST"])
def save_canvas():
    data = request.json
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        user = _auth.auth.get_user(auth_token)
        uid  = user.user.id
        user_db(auth_token).table("users").upsert({
            "id":            uid,
            "email":         user.user.email,
            "canvas_domain": data["domain"],
            "canvas_token":  data["token"],
        }).execute()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/load_canvas", methods=["GET"])
def load_canvas():
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        user = _auth.auth.get_user(auth_token)
        uid  = user.user.id
        res  = user_db(auth_token).table("users").select("canvas_domain, canvas_token").eq("id", uid).execute()
        return jsonify(res.data[0] if res.data else {})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── Canvas helpers ─────────────────────────────────────────────────────────────
def canvas_get(domain, token, endpoint, params={}):
    results = []
    url     = f"https://{domain}/api/v1{endpoint}"
    headers = {"Authorization": f"Bearer {token}"}
    log.info(f'Canvas GET {endpoint} domain={domain}')
    while url:
        r = requests.get(url, headers=headers, params=params, timeout=20)
        log.info(f'Canvas GET {endpoint} -> {r.status_code}')
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            results.extend(data)
        else:
            return data
        url    = r.links.get("next", {}).get("url")
        params = {}
    return results


def get_quarter():
    now = datetime.now(timezone.utc)
    q_ranges = {
        'Q1': ('2025-08-25', '2025-10-17'),
        'Q2': ('2025-10-20', '2026-01-16'),
        'Q3': ('2026-01-20', '2026-03-20'),
        'Q4': ('2026-03-23', '2026-06-12'),
    }
    for q, (s, e) in q_ranges.items():
        start = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        end   = datetime.fromisoformat(e).replace(tzinfo=timezone.utc)
        if start <= now <= end:
            return q
    return 'all'


def format_assignment(a, course_name, now, group_id=None, group_name=None, group_scores=None):
    due_raw    = a.get("due_at")
    due_str    = None
    hours_until = None

    if due_raw:
        due_dt      = datetime.fromisoformat(due_raw.replace("Z", "+00:00"))
        due_str     = due_dt.strftime("%b %d, %I:%M %p")
        hours_until = (due_dt - now).total_seconds() / 3600

    pts          = a.get("points_possible")
    grade_impact = None

    if pts and group_id and group_scores and group_id in group_scores:
        g      = group_scores[group_id]
        weight = g["weight"] / 100
        if g["possible"] > 0:
            other = sum(
                (gs["earned"] / gs["possible"]) * (gs["weight"] / 100)
                for gid2, gs in group_scores.items()
                if gid2 != group_id and gs["possible"] > 0
            )
            cur    = (other + (g["earned"] / g["possible"]) * weight) * 100
            submit = (other + ((g["earned"] + pts) / (g["possible"] + pts)) * weight) * 100
            skip   = (other + (g["earned"] / (g["possible"] + pts)) * weight) * 100
            grade_impact = {
                "current":      round(cur, 1),
                "if_submitted": round(submit, 1),
                "if_missing":   round(skip, 1),
                "swing":        round(submit - skip, 1),
            }

    return {
        "id":           a["id"],
        "name":         a["name"],
        "course":       course_name,
        "group":        group_name,
        "due":          due_str,
        "due_raw":      due_raw,
        "points":       pts,
        "missing":      a.get("is_missing_submission", False),
        "due_soon":     hours_until is not None and 0 < hours_until <= 48,
        "url":          a.get("html_url", ""),
        "grade_impact": grade_impact,
    }


@app.route("/")
@limiter.exempt
def landing():
    resp = send_from_directory("static", "landing.html")
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route("/app")
@limiter.exempt
def index():
    resp = send_from_directory("static", "index.html")
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route("/api/assignments", methods=["POST"])
def get_assignments():
    body   = request.json
    domain = body.get("domain", "").strip().replace("https://", "").replace("/", "")
    token  = body.get("token", "").strip()

    if not domain or not token:
        return jsonify({"error": "Domain and token required"}), 400

    try:
        courses = canvas_get(domain, token, "/courses", {
            "enrollment_state": "active",
            "include[]":        ["total_scores", "current_grading_period_scores"],
            "per_page":         50,
        })
        courses = [c for c in courses if "name" in c and not c.get("access_restricted_by_date")]

        assignments = []
        now         = datetime.now(timezone.utc)

        for course in courses:
            cid   = course["id"]
            cname = course["name"]

            subs = canvas_get(domain, token, f"/courses/{cid}/students/submissions", {
                "student_ids[]": "self",
                "include[]":     "assignment",
                "per_page":      100,
            })

            default_weights = {"perform": 50, "rehearse": 30, "prepare": 20}
            groups = canvas_get(domain, token, f"/courses/{cid}/assignment_groups", {
                "per_page":  50,
                "include[]": "assignments",
            })

            total_weight = sum(g.get("group_weight", 0) for g in groups)
            for g in groups:
                if total_weight == 0:
                    name = g["name"].lower()
                    g["group_weight"] = next((w for k, w in default_weights.items() if k in name), 0)

            group_scores = {}
            for s in subs:
                if s.get("score") is None:
                    continue
                aid = s["assignment_id"]
                for g in groups:
                    if any(a["id"] == aid for a in g.get("assignments", [])):
                        gid = g["id"]
                        if gid not in group_scores:
                            group_scores[gid] = {"earned": 0, "possible": 0, "weight": g["group_weight"]}
                        group_scores[gid]["earned"]   += s["score"]
                        group_scores[gid]["possible"] += (
                            s["assignment"]["points_possible"]
                            if s.get("assignment") and s["assignment"].get("points_possible")
                            else 0
                        )

            for bucket, missing_only in [("future", False), ("past", True)]:
                try:
                    items = canvas_get(domain, token, f"/courses/{cid}/assignments", {
                        "per_page": 100,
                        "bucket":   bucket,
                        "order_by": "due_at",
                    })
                    for a in items:
                        if missing_only and not a.get("is_missing_submission"):
                            continue
                        if not any(x["id"] == a["id"] for x in assignments):
                            gid   = a.get("assignment_group_id")
                            gname = next((g["name"] for g in groups if g["id"] == gid), None)
                            assignments.append(format_assignment(
                                a, cname, now,
                                group_id=gid,
                                group_name=gname,
                                group_scores=group_scores,
                            ))
                except Exception:
                    pass

        assignments.sort(key=lambda a: (0 if a["missing"] else 1, a["due_raw"] or "9999"))

        course_data = []
        for c in courses:
            enrollments = c.get("enrollments") or []
            grade = None
            if enrollments:
                e = enrollments[0]
                grade = (
                    e.get("override_score") if e.get("override_score") is not None
                    else e.get("computed_current_score")
                )
            course_data.append({
                "id":      c["id"],
                "name":    c["name"],
                "grade":   grade,
                "quarter": get_quarter(),
                "source":  "canvas",
            })

        return jsonify({
            "assignments":   assignments,
            "course_count":  len(courses),
            "courses":       course_data,
        })

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            return jsonify({"error": "Invalid token — check your Canvas access token"}), 401
        return jsonify({"error": f"Canvas API error: {e.response.status_code}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
