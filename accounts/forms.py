"""
Accounts forms for registration, authentication, and profile management
"""
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from .models import UserProfile


class UserRegistrationForm(UserCreationForm):
    """User registration form"""
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-control'}))
    firstname = forms.CharField(max_length=100, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}), label='ชื่อ')
    lastname = forms.CharField(max_length=100, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}), label='นามสกุล')
    gender = forms.ChoiceField(choices=UserProfile.GENDER_CHOICES, widget=forms.Select(attrs={'class': 'form-control'}), label='เพศ')
    birthdate = forms.DateField(required=True, widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}), label='วันเกิด')
    age = forms.IntegerField(required=True, widget=forms.NumberInput(attrs={'class': 'form-control'}), label='อายุ')
    phone = forms.CharField(max_length=20, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}), label='เบอร์โทรศัพท์')
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].widget.attrs['class'] = 'form-control'
        self.fields['password2'].widget.attrs['class'] = 'form-control'
        self.fields['username'].label = 'ชื่อผู้ใช้'
        self.fields['email'].label = 'อีเมล'
        self.fields['password1'].label = 'รหัสผ่าน'
        self.fields['password2'].label = 'ยืนยันรหัสผ่าน'


class UserProfileForm(forms.ModelForm):
    """User profile update form"""
    class Meta:
        model = UserProfile
        fields = ['firstname', 'lastname', 'gender', 'birthdate', 'age', 'phone', 'profile_picture', 'nickname']
        widgets = {
            'firstname': forms.TextInput(attrs={'class': 'form-control'}),
            'lastname': forms.TextInput(attrs={'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'birthdate': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'age': forms.NumberInput(attrs={'class': 'form-control', 'min': 1, 'max': 120}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'profile_picture': forms.FileInput(attrs={'class': 'form-control'}),
            'nickname': forms.TextInput(attrs={'class': 'form-control'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make these fields NOT required to allow form submission
        self.fields['firstname'].required = False
        self.fields['lastname'].required = False
        self.fields['gender'].required = False
        self.fields['age'].required = False
        self.fields['phone'].required = False
        # Add labels
        self.fields['firstname'].label = 'ชื่อจริง'
        self.fields['lastname'].label = 'นามสกุล'
        self.fields['gender'].label = 'เพศ'
        self.fields['birthdate'].label = 'วันเกิด'
        self.fields['age'].label = 'อายุ'
        self.fields['phone'].label = 'เบอร์โทรศัพท์'
        self.fields['profile_picture'].label = 'รูปโปรไฟล์'
        self.fields['nickname'].label = 'ชื่อเล่น'
    
    def clean_profile_picture(self):
        """Validate profile picture upload - FAST version"""
        profile_picture = self.cleaned_data.get('profile_picture')
        
        # If no new file uploaded, keep existing
        if not profile_picture:
            return self.instance.profile_picture if self.instance else None
        
        # If it's a file object (new upload), do MINIMAL validation
        if hasattr(profile_picture, 'size'):
            # File size check (9MB max)
            if profile_picture.size > 9 * 1024 * 1024:
                raise forms.ValidationError('ขนาดไฟล์เกิน 9MB')
        
        return profile_picture
    
    def clean(self):
        cleaned_data = super().clean()
        birthdate = cleaned_data.get('birthdate')
        age = cleaned_data.get('age')
        
        # Calculate age from birthdate if provided
        if birthdate:
            from datetime import date
            today = date.today()
            calculated_age = today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))
            if age and abs(age - calculated_age) > 1:
                # Allow 1 year difference for accuracy
                cleaned_data['age'] = calculated_age
        
        return cleaned_data


class MFATokenForm(forms.Form):
    """MFA token verification form"""
    token = forms.CharField(
        max_length=6,
        min_length=6,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control text-center',
            'placeholder': '000000',
            'autocomplete': 'off',
            'inputmode': 'numeric',
            'pattern': '[0-9]*'
        }),
        label='รหัส MFA (6 หลัก)'
    )


class UserManagementForm(forms.ModelForm):
    """Form for admin to manage users"""
    class Meta:
        model = UserProfile
        fields = ['firstname', 'lastname', 'gender', 'age', 'phone', 'role', 'is_active_status', 'is_banned']
        widgets = {
            'firstname': forms.TextInput(attrs={'class': 'form-control'}),
            'lastname': forms.TextInput(attrs={'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'age': forms.NumberInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'role': forms.Select(attrs={'class': 'form-control'}),
            'is_active_status': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_banned': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


class AdminUserCreationForm(forms.ModelForm):
    """Form for admin/superuser to create new users"""
    username = forms.CharField(max_length=150, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}), label='รหัสผ่าน')
    password_confirm = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}), label='ยืนยันรหัสผ่าน')
    
    class Meta:
        model = UserProfile
        fields = ['firstname', 'lastname', 'gender', 'age', 'phone', 'role', 'is_active_status']
        widgets = {
            'firstname': forms.TextInput(attrs={'class': 'form-control'}),
            'lastname': forms.TextInput(attrs={'class': 'form-control'}),
            'gender': forms.Select(attrs={'class': 'form-control'}),
            'age': forms.NumberInput(attrs={'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'class': 'form-control'}),
            'role': forms.Select(attrs={'class': 'form-control'}),
            'is_active_status': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError('รหัสผ่านไม่ตรงกัน')
        
        return cleaned_data
