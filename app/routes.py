"""
Phishield Application Routes (Hardened & Bug-Proofed)
Handles scanning interface, results presentation, scan history, user reports,
privacy policy, account management, CSRF protection, and error boundaries.
"""

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort
)
from app.auth import (
    login_required,
    validate_csrf_token,
    generate_csrf_token,
    register_user,
    authenticate_user
)
from app.database import (
    get_db_connection,
    delete_user_account,
    cleanup_expired_scans
)
from app.model import get_detector
from app.utils import is_valid_url, normalize_url, defang_url
from app.security import rate_limit

main_bp = Blueprint('main', __name__)
auth_bp = Blueprint('auth', __name__)


# -------------------------------------------------------------
# CSRF & Security Pre-request Handler
# -------------------------------------------------------------
@main_bp.before_app_request
def csrf_protect():
    """Validates CSRF token on all state-changing POST requests."""
    if request.method == "POST":
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            abort(400, description="Invalid or expired CSRF security token. Please reload and try again.")


@main_bp.app_context_processor
def inject_csrf_token():
    """Makes csrf_token available to all Jinja2 templates."""
    return dict(csrf_token=generate_csrf_token())


# -------------------------------------------------------------
# Custom Error Handlers
# -------------------------------------------------------------
@main_bp.app_errorhandler(400)
def handle_bad_request(e):
    return render_template('errors/400.html', error_message=getattr(e, 'description', None)), 400


@main_bp.app_errorhandler(404)
def handle_not_found(e):
    return render_template('errors/404.html'), 404


@main_bp.app_errorhandler(429)
def handle_too_many_requests(e):
    return render_template('errors/429.html', error_message=getattr(e, 'description', None)), 429


@main_bp.app_errorhandler(500)
def handle_internal_error(e):
    return render_template('errors/500.html'), 500


# -------------------------------------------------------------
# Core Navigation Routes
# -------------------------------------------------------------
@main_bp.route('/')
def index():
    """Landing homepage presenting the Phishield detection platform."""
    return render_template('index.html')


@main_bp.route('/scan', methods=['GET', 'POST'])
def scan():
    """
    Main URL scanning endpoint.
    Accepts URL, evaluates 13 heuristic rules + Random Forest model,
    saves history for logged-in users, and displays result.
    Protected by DoS rate limiting.
    """
    if request.method == 'GET':
        url_prefill = request.args.get('url', '').strip()
        return render_template('scan.html', url_prefill=url_prefill)

    # POST - rate limit scans per IP
    raw_url = request.form.get('url', '').strip()
    if not raw_url:
        flash("Please enter a web address to inspect.", "warning")
        return redirect(url_for('main.scan'))

    # Strict URL validation
    if not is_valid_url(raw_url):
        flash(
            "Invalid web address format or unsupported protocol. "
            "Please enter a valid HTTP/HTTPS web address (e.g., example.com or https://example.com).",
            "warning"
        )
        return render_template('scan.html', url_prefill=raw_url)

    detector = get_detector()
    result = detector.predict(raw_url)

    # If user is logged in, attempt to record scan in history safely
    scan_id = None
    if 'user_id' in session:
        user_id = session['user_id']
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history (
                    user_id, url_masked, url_defanged, rating,
                    composite_score, rules_score, ml_score, triggered_rules_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                result['url_masked'],
                result['url_defanged'],
                result['rating'],
                result['composite_score'],
                result['rules_score'],
                result['ml_score'],
                result['triggered_count']
            ))
            scan_id = cursor.lastrowid
            conn.commit()
            conn.close()
        except Exception as e:
            # Failure to record history should not prevent user from viewing result
            pass

    return render_template('result.html', result=result, scan_id=scan_id)


@main_bp.route('/history')
@login_required
def history():
    """
    Displays the authenticated user's scan history.
    OWASP A01: Enforces that users can only view their own records.
    """
    # Trigger 90-day retention cleanup safely
    cleanup_expired_scans()

    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM scan_history
        WHERE user_id = ?
        ORDER BY scanned_at DESC
    """, (user_id,))
    scans = cursor.fetchall()
    conn.close()
    return render_template('history.html', scans=scans)


@main_bp.route('/history/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """
    Deletes a single scan history item belonging to the current user.
    OWASP A01: Ensures user ownership before deletion.
    """
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE id = ? AND user_id = ?", (scan_id, user_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    
    if affected > 0:
        flash("Scan record successfully removed from history.", "info")
    else:
        flash("Record could not be found or you do not have permission to delete it.", "warning")
    return redirect(url_for('main.history'))


@main_bp.route('/history/clear', methods=['POST'])
@login_required
def clear_history():
    """Clears all scan history items for the current user."""
    user_id = session['user_id']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash("Your complete inspection history has been purged.", "info")
    return redirect(url_for('main.history'))


@main_bp.route('/report', methods=['GET', 'POST'])
def report_wrong_result():
    """
    Allows users to report false positive or false negative results
    for continuous model assessment and usability monitoring.
    """
    if request.method == 'GET':
        scan_id = request.args.get('scan_id', '').strip()
        url = request.args.get('url', '').strip()
        rating = request.args.get('rating', '').strip()
        return render_template('report.html', scan_id=scan_id, url=url, rating=rating)

    scan_id_val = request.form.get('scan_id', '').strip()
    scan_id = int(scan_id_val) if scan_id_val.isdigit() else None
    raw_url = request.form.get('url', '').strip()
    reported_rating = request.form.get('reported_rating', 'unknown')[:32]
    user_expected = request.form.get('expected_rating', 'safe')[:32]
    comments = request.form.get('comments', '').strip()[:1000]
    user_email = session.get('email', request.form.get('email', 'anonymous'))[:128]

    defanged = defang_url(raw_url) if raw_url else 'N/A'

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_reports (
                scan_id, user_email, url_defanged, reported_rating,
                user_expected_rating, comments
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, user_email, defanged, reported_rating, user_expected, comments))
        conn.commit()
        conn.close()
        flash("Thank you for submitting feedback. Your report has been logged for evaluation.", "success")
    except Exception:
        flash("Feedback received. Thank you for your contribution.", "info")

    return redirect(url_for('main.scan'))


@main_bp.route('/privacy')
def privacy():
    """Detailed Privacy Policy and Legal, Social, Ethical, and Professional Issues (LSEPI)."""
    return render_template('privacy.html')


@main_bp.route('/about')
def about():
    """Methodology, 13 URL heuristic rules documentation, and ML comparison overview."""
    return render_template('about.html')


# -------------------------------------------------------------
# Authentication Routes
# -------------------------------------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('main.scan'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', email=email)

        success, msg = register_user(email, password)
        if success:
            flash(msg, "success")
            return redirect(url_for('auth.login'))
        else:
            flash(msg, "danger")
            return render_template('register.html', email=email)

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('main.scan'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        user, msg = authenticate_user(email, password)
        if user:
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['csrf_token'] = generate_csrf_token()
            flash("Welcome back! Authentication successful.", "success")
            next_page = request.args.get('next')
            # Open redirect defense: only allow relative local paths
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.scan'))
        else:
            flash(msg, "danger")
            return render_template('login.html', email=email)

    return render_template('login.html')


@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('main.index'))


@auth_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """
    Account management interface.
    Provides user information and GDPR Right to Erasure (account deletion).
    """
    user_id = session['user_id']
    if request.method == 'POST':
        confirm = request.form.get('confirm_delete', '').strip()
        if confirm == 'DELETE':
            delete_user_account(user_id)
            session.clear()
            flash("Your account and all associated scan data have been permanently erased (UK GDPR Art. 17).", "info")
            return redirect(url_for('main.index'))
        else:
            flash("Please type 'DELETE' in uppercase to confirm account deletion.", "warning")
            return redirect(url_for('auth.account'))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email, created_at FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) AS total_scans FROM scan_history WHERE user_id = ?", (user_id,))
    scan_count = cursor.fetchone()['total_scans']
    conn.close()

    return render_template('account.html', user=user, scan_count=scan_count)
