"""
Accounts views for user management, authentication, and MFA
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.urls import reverse_lazy
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
import qrcode
import io
import base64
import logging
import json
from .models import UserProfile, UserActivity
from .forms import (
    UserRegistrationForm, UserProfileForm, MFATokenForm,
    UserManagementForm, AdminUserCreationForm
)

# Set up logging
logger = logging.getLogger(__name__)

def home_view(request):
    return render(request, 'home.html')

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_activity(user, action, description='', request=None):
    """Log user activity"""
    activity = UserActivity.objects.create(
        user=user,
        action=action,
        description=description
    )
    if request:
        activity.ip_address = get_client_ip(request)
        activity.user_agent = request.META.get('HTTP_USER_AGENT', '')
        activity.save()


def register_view(request):
    """User registration view - users start as inactive"""
    if request.user.is_authenticated:
        return redirect('health_app:dashboard')
    
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            # Create user but don't save yet
            user = form.save(commit=False)
            user.is_active = False  # User starts inactive
            user.save()
            
            # Create/update profile
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.firstname = form.cleaned_data['firstname']
            profile.lastname = form.cleaned_data['lastname']
            profile.gender = form.cleaned_data['gender']
            profile.age = form.cleaned_data['age']
            profile.phone = form.cleaned_data['phone']
            profile.is_active_status = False  # Needs admin approval
            profile.role = 'normal'
            profile.save()
            
            log_activity(user, 'profile_update', 'User registered - awaiting approval', request)
            
            messages.success(request, 'ลงทะเบียนสำเร็จ! รอการอนุมัติจากผู้ดูแลระบบ')
            return redirect('accounts:login')
    else:
        form = UserRegistrationForm()
    
    return render(request, 'accounts/register.html', {'form': form})


@ratelimit(key='ip', rate='10/m', method='POST', block=False)
@ratelimit(key='post:username', rate='5/h', method='POST', block=False)
def login_view(request):
    """Login view with MFA support, rate limiting, and account lockout"""
    if request.user.is_authenticated:
        return redirect('health_app:dashboard')
    
    # Check if rate limited
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        messages.error(request, '⚠️ คุณพยายามเข้าสู่ระบบบ่อยเกินไป กรุณารอสักครู่')
        logger.warning(f'Rate limit exceeded for IP: {get_client_ip(request)}')
        return render(request, 'accounts/login.html')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        client_ip = get_client_ip(request)
        
        # Check if account is locked
        lockout_key = f'account_lockout:{username}'
        if cache.get(lockout_key):
            remaining_time = cache.ttl(lockout_key) // 60
            messages.error(request, f'🔒 บัญชีถูกล็อคชั่วคราว กรุณารออีก {remaining_time} นาที')
            logger.warning(f'Login attempt on locked account: {username} from {client_ip}')
            return render(request, 'accounts/login.html')
        
        # Track login attempts
        attempts_key = f'login_attempts:{username}'
        attempts = cache.get(attempts_key, 0)
        
        # Track login attempt
        try:
            from security_enhancements.security_audit import SecurityAuditTracker, SecurityEventTypes, SecurityEventSeverity
        except ImportError:
            SecurityAuditTracker = None
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Clear failed attempts on successful authentication
            cache.delete(attempts_key)
            
            # Check if user is active
            if not user.is_active or not user.profile.is_active_status:
                messages.error(request, 'บัญชีของคุณยังไม่ได้รับการอนุมัติหรือถูกระงับ')
                return redirect('accounts:login')
            
            # Check if banned
            if user.profile.is_banned:
                messages.error(request, 'บัญชีของคุณถูกแบน')
                return redirect('accounts:login')
            
            # Check if profile is complete
            if not user.profile.firstname or not user.profile.lastname:
                messages.warning(request, 'กรุณาเพิ่มข้อมูลโปรไฟล์ให้ครบถ้วน')
                # Regenerate session to prevent fixation
                login(request, user)
                request.session.cycle_key()
                return redirect('accounts:profile')
            
            # Check if user requires MFA
            if user.profile.requires_mfa():
                # Check if MFA is already setup
                if user.profile.mfa_enabled:
                    # MFA is setup, verify the code
                    request.session['pre_mfa_user_id'] = user.id
                    request.session['pre_mfa_username'] = user.username
                    return redirect('accounts:mfa_verify')
                else:
                    # MFA is required but not setup yet, login and redirect to setup
                    login(request, user)
                    # Regenerate session to prevent fixation
                    request.session.cycle_key()
                    user.profile.last_login_at = timezone.now()
                    user.profile.save()
                    log_activity(user, 'login', f'Logged in from {get_client_ip(request)} - MFA setup required', request)
                    messages.warning(request, '⚠️ คุณต้องตั้งค่า MFA (Google Authenticator) เพื่อความปลอดภัย')
                    return redirect('accounts:mfa_setup')
            else:
                # No MFA required, login directly
                login(request, user)
                # Regenerate session to prevent fixation
                request.session.cycle_key()
                user.profile.last_login_at = timezone.now()
                user.profile.save()
                log_activity(user, 'login', f'Logged in from {client_ip}', request)
                
                # Log successful login security event
                if SecurityAuditTracker:
                    SecurityAuditTracker.log_security_event(
                        SecurityEventTypes.LOGIN_SUCCESS,
                        f'User {username} successfully logged in',
                        user=user,
                        ip_address=client_ip,
                        severity=SecurityEventSeverity.LOW
                    )
                
                messages.success(request, f'ยินดีต้อนรับ {user.profile.firstname or user.username}!')
                return redirect('health_app:dashboard')
        else:
            # Increment failed attempts
            attempts += 1
            cache.set(attempts_key, attempts, 3600)  # 1 hour expiry
            
            # Lock account after 5 failed attempts
            if attempts >= 5:
                cache.set(lockout_key, True, 1800)  # 30 minutes lockout
                messages.error(request, '🔒 บัญชีถูกล็อคเนื่องจากพยายามเข้าสู่ระบบล้มเหลวหลายครั้ง (30 นาที)')
                logger.warning(f'Account locked due to failed attempts: {username} from {client_ip}')
                
                # Log security event
                if SecurityAuditTracker:
                    SecurityAuditTracker.log_security_event(
                        SecurityEventTypes.LOGIN_FAILED,
                        f'Account locked: {username} after {attempts} failed attempts',
                        ip_address=client_ip,
                        severity=SecurityEventSeverity.HIGH,
                        additional_data={'attempted_username': username, 'attempts': attempts}
                    )
            else:
                remaining = 5 - attempts
                messages.error(request, f'❌ ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง (เหลือ {remaining} ครั้ง)')
                logger.info(f'Failed login attempt {attempts}/5 for {username} from {client_ip}')
            
            # Log failed login attempt
            if SecurityAuditTracker:
                SecurityAuditTracker.log_security_event(
                    SecurityEventTypes.LOGIN_FAILED,
                    f'Failed login attempt for username: {username}',
                    ip_address=client_ip,
                    severity=SecurityEventSeverity.MEDIUM,
                    additional_data={'attempted_username': username, 'attempts': attempts}
                )
    
    return render(request, 'accounts/login.html')


@ratelimit(key='user_or_ip', rate='3/5m', method='POST', block=False)
@ratelimit(key='ip', rate='10/h', method='POST', block=False)
def mfa_verify_view(request):
    """MFA verification view with rate limiting and lockout protection"""
    # Check if user is in pre-MFA session
    if 'pre_mfa_user_id' not in request.session:
        messages.error(request, 'เซสชันหมดอายุ กรุณาล็อกอินใหม่')
        return redirect('accounts:login')
    
    # Check if rate limited
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        messages.error(request, '⚠️ คุณพยายามยืนยัน MFA บ่อยเกินไป กรุณารอสักครู่')
        return render(request, 'accounts/mfa_verify.html', {
            'form': MFATokenForm(),
            'username': request.session.get('pre_mfa_username')
        })
    
    user_id = request.session.get('pre_mfa_user_id')
    user = get_object_or_404(User, id=user_id)
    
    # Check MFA lockout
    mfa_lockout_key = f'mfa_lockout:{user.id}'
    if cache.get(mfa_lockout_key):
        remaining_time = cache.ttl(mfa_lockout_key) // 60
        messages.error(request, f'🔒 MFA ถูกล็อคชั่วคราว กรุณารออีก {remaining_time} นาที')
        logger.warning(f'MFA verification attempted on locked account: {user.username}')
        return render(request, 'accounts/mfa_verify.html', {
            'form': MFATokenForm(),
            'username': request.session.get('pre_mfa_username'),
            'locked': True
        })
    
    if request.method == 'POST':
        form = MFATokenForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            
            # Track failed MFA attempts
            mfa_attempts_key = f'mfa_attempts:{user.id}'
            attempts = cache.get(mfa_attempts_key, 0)
            
            if user.profile.verify_mfa_token(token):
                # Clear attempts on success
                cache.delete(mfa_attempts_key)
                
                # MFA successful - login user
                login(request, user)
                # Regenerate session to prevent fixation
                request.session.cycle_key()
                
                user.profile.last_login_at = timezone.now()
                user.profile.save()
                
                # Clear pre-MFA session
                del request.session['pre_mfa_user_id']
                del request.session['pre_mfa_username']
                
                log_activity(user, 'login', f'Logged in with MFA from {get_client_ip(request)}', request)
                logger.info(f'MFA verification successful for {user.username}')
                messages.success(request, f'✅ ยินดีต้อนรับ {user.profile.firstname}!')
                return redirect('health_app:dashboard')
            else:
                # Increment failed attempts
                attempts += 1
                cache.set(mfa_attempts_key, attempts, 900)  # 15 minutes expiry
                
                # Lock MFA after 3 failed attempts
                if attempts >= 3:
                    cache.set(mfa_lockout_key, True, 900)  # 15 minutes lockout
                    messages.error(request, '🔒 MFA ล้มเหลวหลายครั้ง บัญชีถูกล็อคชั่วคราว (15 นาที)')
                    logger.warning(f'MFA locked for user {user.username} after {attempts} failed attempts')
                    
                    # Log security event
                    try:
                        from security_enhancements.security_audit import SecurityAuditTracker, SecurityEventTypes, SecurityEventSeverity
                        SecurityAuditTracker.log_security_event(
                            SecurityEventTypes.LOGIN_FAILED,
                            f'MFA locked: {user.username} after {attempts} failed attempts',
                            user=user,
                            ip_address=get_client_ip(request),
                            severity=SecurityEventSeverity.HIGH
                        )
                    except ImportError:
                        pass
                    
                    return render(request, 'accounts/mfa_verify.html', {
                        'form': form,
                        'username': request.session.get('pre_mfa_username'),
                        'locked': True
                    })
                else:
                    remaining = 3 - attempts
                    messages.error(request, f'❌ รหัส MFA ไม่ถูกต้อง (เหลือ {remaining} ครั้ง)')
                    logger.info(f'Failed MFA attempt {attempts}/3 for {user.username}')
    else:
        form = MFATokenForm()
    
    return render(request, 'accounts/mfa_verify.html', {
        'form': form,
        'username': request.session.get('pre_mfa_username')
    })


@login_required
def mfa_setup_view(request):
    """MFA setup view for admin/superuser"""
    if not request.user.profile.requires_mfa():
        messages.error(request, 'MFA ไม่จำเป็นสำหรับบัญชีของคุณ')
        return redirect('accounts:profile')
    
    profile = request.user.profile
    
    # Generate MFA secret if not exists
    if not profile.mfa_secret:
        profile.generate_mfa_secret()
    
    # Generate QR code
    qr_uri = profile.get_mfa_uri()
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    if request.method == 'POST':
        form = MFATokenForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            if profile.verify_mfa_token(token):
                profile.mfa_enabled = True
                profile.save()
                messages.success(request, 'เปิดใช้งาน MFA สำเร็จ!')
                return redirect('accounts:profile')
            else:
                messages.error(request, 'รหัส MFA ไม่ถูกต้อง กรุณาลองใหม่')
    else:
        form = MFATokenForm()
    
    return render(request, 'accounts/mfa_setup.html', {
        'form': form,
        'qr_code': qr_code_base64,
        'secret_key': profile.mfa_secret
    })


@login_required
def profile_view(request):
    """User profile view"""
    profile = request.user.profile
    
    # Check if profile is incomplete
    profile_incomplete = not profile.firstname or not profile.lastname or not profile.age
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            try:
                saved_profile = form.save()
                log_activity(request.user, 'profile_update', 'Profile updated', request)
                messages.success(request, 'อัปเดตโปรไฟล์สำเร็จ!')
                return redirect('accounts:profile')
            except Exception as e:
                messages.error(request, f'เกิดข้อผิดพลาดในการบันทึก: {str(e)}')
        else:
            # Add specific error messages for each field with errors
            for field, errors in form.errors.items():
                field_label = form.fields.get(field, {}).label or field
                for error in errors:
                    messages.error(request, f'{field_label}: {error}')
    else:
        form = UserProfileForm(instance=profile)
    
    # Check if MFA is required but not enabled
    mfa_warning = profile.requires_mfa() and not profile.mfa_enabled
    mfa_required_but_not_setup = mfa_warning  # More descriptive variable name
    
    return render(request, 'accounts/profile.html', {
        'form': form,
        'profile': profile,
        'mfa_warning': mfa_warning,
        'mfa_required_but_not_setup': mfa_required_but_not_setup,
        'profile_incomplete': profile_incomplete,
    })


@login_required
def logout_view(request):
    """Logout view"""
    log_activity(request.user, 'logout', f'Logged out from {get_client_ip(request)}', request)
    logout(request)
    messages.success(request, 'ออกจากระบบสำเร็จ')
    return redirect('accounts:login')


# Admin-only views
def is_admin(user):
    """Check if user is admin or superuser"""
    return user.is_authenticated and user.profile.role in ['admin', 'superuser']


def is_superuser(user):
    """Check if user is superuser"""
    return user.is_authenticated and user.profile.role == 'superuser'


@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    """Admin dashboard with user management"""
    users = User.objects.select_related('profile').all().order_by('-date_joined')
    
    # Filter options
    status_filter = request.GET.get('status', 'all')
    role_filter = request.GET.get('role', 'all')
    search_query = request.GET.get('search', '')
    
    if status_filter == 'active':
        users = users.filter(profile__is_active_status=True, profile__is_banned=False)
    elif status_filter == 'inactive':
        users = users.filter(profile__is_active_status=False)
    elif status_filter == 'banned':
        users = users.filter(profile__is_banned=True)
    
    if role_filter != 'all':
        users = users.filter(profile__role=role_filter)
    
    if search_query:
        users = users.filter(
            Q(username__icontains=search_query) |
            Q(email__icontains=search_query) |
            Q(profile__firstname__icontains=search_query) |
            Q(profile__lastname__icontains=search_query)
        )
    
    # Get recent activities
    recent_activities = UserActivity.objects.select_related('user').all()[:50]
    
    # Statistics
    total_users = User.objects.count()
    active_users = UserProfile.objects.filter(is_active_status=True, is_banned=False).count()
    pending_users = UserProfile.objects.filter(is_active_status=False, is_banned=False).count()
    banned_users = UserProfile.objects.filter(is_banned=True).count()
    
    context = {
        'users': users,
        'recent_activities': recent_activities,
        'total_users': total_users,
        'active_users': active_users,
        'pending_users': pending_users,
        'banned_users': banned_users,
        'status_filter': status_filter,
        'role_filter': role_filter,
        'search_query': search_query,
    }
    
    return render(request, 'accounts/admin_dashboard.html', context)


@login_required
@user_passes_test(is_admin)
def user_management_view(request, user_id):
    """User management view for admin"""
    managed_user = get_object_or_404(User, id=user_id)
    profile = managed_user.profile
    
    # Superuser restrictions
    if profile.role == 'admin' and request.user.profile.role != 'superuser':
        messages.error(request, 'คุณไม่มีสิทธิ์จัดการแอดมิน')
        return redirect('accounts:admin_dashboard')
    
    if request.method == 'POST':
        form = UserManagementForm(request.POST, instance=profile)
        if form.is_valid():
            # Role change restrictions
            if profile.role == 'admin' and request.user.profile.role != 'superuser':
                messages.error(request, 'เฉพาะ Superuser เท่านั้นที่จัดการแอดมินได้')
                return redirect('accounts:admin_dashboard')
            
            old_status = profile.is_active_status
            form.save()
            
            # Update user.is_active based on profile status
            managed_user.is_active = profile.is_active_status and not profile.is_banned
            managed_user.save()
            
            # Log the change
            if old_status != profile.is_active_status:
                status = 'approved' if profile.is_active_status else 'deactivated'
                log_activity(managed_user, 'status_change', f'Status changed to {status} by {request.user.username}', request)
            
            messages.success(request, 'อัปเดตข้อมูลผู้ใช้สำเร็จ!')
            return redirect('accounts:admin_dashboard')
    else:
        form = UserManagementForm(instance=profile)
    
    return render(request, 'accounts/user_management.html', {
        'form': form,
        'managed_user': managed_user,
        'profile': profile
    })


@login_required
@user_passes_test(is_admin)
def user_delete_view(request, user_id):
    """Delete user (admin only)"""
    managed_user = get_object_or_404(User, id=user_id)
    
    if managed_user.profile.role in ['admin', 'superuser'] and request.user.profile.role != 'superuser':
        messages.error(request, 'คุณไม่มีสิทธิ์ลบแอดมิน')
        return redirect('accounts:admin_dashboard')
    
    if request.method == 'POST':
        username = managed_user.username
        managed_user.delete()
        messages.success(request, f'ลบผู้ใช้ {username} สำเร็จ!')
        return redirect('accounts:admin_dashboard')
    
    return render(request, 'accounts/user_delete_confirm.html', {'managed_user': managed_user})


@login_required
@user_passes_test(is_admin)
def user_create_view(request):
    """Create new user (admin only)"""
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if form.is_valid():
            # Check role permissions
            role = form.cleaned_data['role']
            if role in ['admin', 'superuser'] and request.user.profile.role != 'superuser':
                messages.error(request, 'เฉพาะ Superuser เท่านั้นที่สร้างแอดมินได้')
                return redirect('accounts:admin_dashboard')
            
            # Create user
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_active = form.cleaned_data['is_active_status']
            user.save()
            
            # Update profile
            profile = user.profile
            profile.firstname = form.cleaned_data['firstname']
            profile.lastname = form.cleaned_data['lastname']
            profile.gender = form.cleaned_data['gender']
            profile.age = form.cleaned_data['age']
            profile.phone = form.cleaned_data['phone']
            profile.role = form.cleaned_data['role']
            profile.is_active_status = form.cleaned_data['is_active_status']
            profile.save()
            
            log_activity(user, 'profile_update', f'User created by {request.user.username}', request)
            messages.success(request, f'สร้างผู้ใช้ {username} สำเร็จ!')
            return redirect('accounts:admin_dashboard')
    else:
        form = AdminUserCreationForm()
    
    return render(request, 'accounts/user_create.html', {'form': form})


# Password Reset Views
class CustomPasswordResetView(PasswordResetView):
    """Custom password reset view"""
    template_name = 'accounts/password_reset.html'
    email_template_name = 'accounts/password_reset_email.html'
    subject_template_name = 'accounts/password_reset_subject.txt'
    success_url = reverse_lazy('accounts:password_reset_done')


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """Custom password reset confirm view"""
    template_name = 'accounts/password_reset_confirm.html'
    success_url = reverse_lazy('accounts:password_reset_complete')


@login_required
@user_passes_test(is_admin)
def enhance_security(request):
    """Comprehensive security enhancement view with real-time audit data"""
    from django.core.cache import cache
    from security_enhancements.dashboard_data_handler import SecurityDashboardDataHandler
    import json
    
    # Log admin access to security dashboard
    try:
        from security_enhancements.security_audit import SecurityAuditTracker, SecurityEventTypes, SecurityEventSeverity
        SecurityAuditTracker.log_security_event(
            SecurityEventTypes.ADMIN_ACCESS,
            f'Admin {request.user.username} accessed security dashboard',
            user=request.user,
            ip_address=get_client_ip(request),
            severity=SecurityEventSeverity.LOW
        )
    except ImportError:
        pass
    
    try:
        # Ensure security data is populated with real data
        SecurityDashboardDataHandler.populate_realtime_security_data()
        
        # Get comprehensive security data
        security_overview = SecurityDashboardDataHandler.get_dashboard_overview()
        
        # Get real-time security audit data
        try:
            from security_enhancements.security_audit import SecurityAuditTracker
            audit_summary = SecurityAuditTracker.get_security_summary()
            recent_security_events = SecurityAuditTracker.get_security_events(limit=20)
        except ImportError:
            audit_summary = {}
            recent_security_events = []
        
        # Get detailed security metrics from cache
        security_data = {
            # Real-time metrics
            'realtime_metrics': cache.get('security_realtime_metrics', {}),
            
            # Threat intelligence
            'threat_intelligence': cache.get('threat_intelligence_summary', {}),
            
            # Attacking IPs with details
            'attacking_ips': cache.get('top_attacking_ips', {}),
            
            # Attack types distribution
            'attack_types': cache.get('top_attack_types', {}),
            
            # Targeted paths
            'targeted_paths': cache.get('top_targeted_paths', {}),
            
            # Geographic distribution
            'geographic_threats': cache.get('geographic_threat_distribution', {}),
            
            # Threat actors analysis
            'threat_actors': cache.get('threat_actors_analysis', {}),
            
            # Incidents summary
            'incidents': cache.get('incident_summary', {}),
            
            # Anomaly detection
            'anomalies': cache.get('anomaly_detection_summary', {}),
            
            # System health
            'system_health': cache.get('system_health_summary', {}),
            
            # Timeline data
            'timeline_events': cache.get('threat_timeline_cache', [])[:20],  # Last 20 events
        }
        
        # Security modules status
        modules_status = security_data.get('realtime_metrics', {}).get('modules_status', {})
        if not modules_status and 'security_overview_data' in cache:
            overview_data = cache.get('security_overview_data', {})
            modules_status = overview_data.get('modules_status', {})
        
        # Security statistics
        security_stats = {
            'total_requests_24h': security_data['realtime_metrics'].get('total_requests', 0),
            'threat_events': security_data['realtime_metrics'].get('high_threat_requests', 0),
            'blocked_requests': security_data['realtime_metrics'].get('blocked_requests', 0),
            'unique_ips': security_data['realtime_metrics'].get('unique_ips', 0),
            'avg_threat_score': security_data['realtime_metrics'].get('avg_threat_score', 0.0),
            'malicious_ips': security_data['threat_intelligence'].get('malicious_ips', 0),
            'suspicious_domains': security_data['threat_intelligence'].get('suspicious_domains', 0),
            'total_incidents': security_data['incidents'].get('total_incidents', 0),
            'critical_incidents': security_data['incidents'].get('critical_incidents', 0),
            'open_incidents': security_data['incidents'].get('open_incidents', 0),
        }
        
        # Top threats analysis
        top_threats = {
            'attacking_ips': list(security_data['attacking_ips'].items())[:10],
            'attack_types': list(security_data['attack_types'].items())[:10],
            'targeted_paths': list(security_data['targeted_paths'].items())[:10],
        }
        
        # System performance metrics
        performance_metrics = security_data['system_health'].get('performance_metrics', {})
        
        # Security engine status
        security_engines = security_data['system_health'].get('security_engines', {})
        
        # Recent security events for display
        recent_events = security_data['timeline_events'][:15]
        
        # Format data for better display
        for event in recent_events:
            if isinstance(event.get('timestamp'), str):
                try:
                    from datetime import datetime
                    event['formatted_time'] = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    event['formatted_time'] = event.get('timestamp', 'Unknown')
        
        context = {
            'page_title': 'Security Enhancement Dashboard - Real-Time Monitoring',
            'security_data': security_data,
            'security_overview': security_overview,
            'security_stats': security_stats,
            'top_threats': top_threats,
            'modules_status': modules_status,
            'performance_metrics': performance_metrics,
            'security_engines': security_engines,
            'recent_events': recent_events,
            'audit_summary': audit_summary,
            'recent_security_events': recent_security_events,
            'data_last_updated': security_data['realtime_metrics'].get('last_updated', 'Unknown'),
            'is_real_data': True,  # Flag to indicate this is real system data
        }
        
        return render(request, 'accounts/enhance_security.html', context)
        
    except Exception as e:
        messages.error(request, f'เกิดข้อผิดพลาดในการโหลดข้อมูลความปลอดภัย: {str(e)}')
        return redirect('accounts:admin_dashboard')


@login_required
@user_passes_test(is_admin)
def reset_security_data(request):
    """
    Reset all security data from cache and storage with security audit logging
    """
    logger = logging.getLogger(__name__)
    
    # Log security data reset attempt
    try:
        from security_enhancements.security_audit import SecurityAuditTracker, SecurityEventTypes, SecurityEventSeverity
        SecurityAuditTracker.log_security_event(
            SecurityEventTypes.ADMIN_ACCESS,
            f'Admin {request.user.username} initiated security data reset',
            user=request.user,
            ip_address=get_client_ip(request),
            severity=SecurityEventSeverity.HIGH
        )
    except ImportError:
        pass
    
    # Log the request details
    logger.info(f"Reset security data request received from user: {request.user.username}")
    logger.info(f"Request method: {request.method}")
    logger.info(f"Is AJAX: {request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'}")
    logger.info(f"Content-Type: {request.META.get('CONTENT_TYPE', 'Not specified')}")
    
    # Only allow POST requests
    if request.method != 'POST':
        logger.warning(f"Invalid method {request.method} for reset request")
        return JsonResponse({'status': 'error', 'message': 'Only POST requests allowed'}, status=405)
    
    try:
        # List of all security-related cache keys to clear
        security_cache_keys = [
            # Dashboard data
            'security_dashboard_overview',
            'security_dashboard_threats',
            'security_dashboard_attacks',
            'security_dashboard_performance',
            'security_dashboard_timeline',
            'security_dashboard_modules',
            'security_overview_data',
            
            # Monitoring data
            'security_monitoring_data',
            'threat_detection_data',
            'attack_statistics',
            'blocked_ips',
            'security_events',
            'security_metrics',
            'security_realtime_metrics',
            
            # Real-time data
            'realtime_threats',
            'realtime_attacks',
            'realtime_performance',
            'system_health_data',
            'system_health_summary',
            
            # Analytics data
            'security_analytics',
            'threat_intelligence_summary',
            'security_reports',
            'incident_data',
            'incident_summary',
            
            # Attack data
            'top_attacking_ips',
            'top_attack_types',
            'top_targeted_paths',
            'geographic_threat_distribution',
            'threat_actors_analysis',
            'anomaly_detection_summary',
            'threat_timeline_cache',
            
            # Configuration data
            'security_config',
            'monitoring_config',
            'alert_config'
        ]
        
        # Clear all security-related cache keys
        cleared_keys = []
        for key in security_cache_keys:
            try:
                if cache.get(key) is not None:
                    cache.delete(key)
                    cleared_keys.append(key)
            except Exception as e:
                logger.warning(f"Failed to clear cache key {key}: {str(e)}")
        
        # Clear any cache keys that start with security patterns
        try:
            # This is a more comprehensive approach for Django cache backends that support it
            if hasattr(cache, 'delete_pattern'):
                cache.delete_pattern('security_*')
                cache.delete_pattern('threat_*')
                cache.delete_pattern('attack_*')
                cache.delete_pattern('monitoring_*')
        except Exception as e:
            logger.warning(f"Pattern-based cache clearing failed: {str(e)}")
        
        # Reset security data using the data handler if available
        try:
            from security_enhancements.dashboard_data_handler import SecurityDashboardDataHandler
            handler = SecurityDashboardDataHandler()
            # Clear any persistent data if the handler supports it
            if hasattr(handler, 'reset_all_data'):
                handler.reset_all_data()
        except ImportError:
            logger.warning("SecurityDashboardDataHandler not available for reset")
        except Exception as e:
            logger.warning(f"Failed to reset data via handler: {str(e)}")
        
        logger.info(f"Security data reset completed by user {request.user.username}. Cleared {len(cleared_keys)} cache keys.")
        
        # Check if it's an AJAX request
        if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
            # Return JSON response for AJAX
            return JsonResponse({
                'status': 'success',
                'message': f'Successfully reset all security data. Cleared {len(cleared_keys)} data entries.',
                'cleared_keys': len(cleared_keys)
            })
        else:
            # Return redirect for form submission
            messages.success(request, f'✅ Security data reset successful! Cleared {len(cleared_keys)} cache entries.')
            return redirect('accounts:enhance_security')
        
    except Exception as e:
        logger.error(f"Error resetting security data: {str(e)}")
        
        # Check if it's an AJAX request
        if request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
            return JsonResponse({
                'status': 'error',
                'message': f'Failed to reset security data: {str(e)}'
            }, status=500)
        else:
            messages.error(request, f'❌ Failed to reset security data: {str(e)}')
            return redirect('accounts:enhance_security')
