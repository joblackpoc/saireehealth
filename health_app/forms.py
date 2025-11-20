"""
Health App forms for health record management
"""
from django import forms
from .models import HealthRecord


class HealthRecordForm(forms.ModelForm):
    """Form for creating and updating health records"""
    class Meta:
        model = HealthRecord
        fields = [
            'blood_pressure_systolic', 'blood_pressure_diastolic',
            'height', 'weight', 'waist',
            'cholesterol', 'ldl', 'hdl', 'fbs', 'triglycerides',
            'bmi', 'fat_percent', 'visceral_fat', 'muscle_percent',
            'bmr', 'body_age', 'recorded_at'
        ]
        widgets = {
            'blood_pressure_systolic': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'ความดันบน'}),
            'blood_pressure_diastolic': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'ความดันล่าง'}),
            'height': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'ส่วนสูง (cm)'}),
            'weight': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'น้ำหนัก (kg)'}),
            'waist': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'เส้นรอบเอว (cm)'}),
            'cholesterol': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'Cholesterol (mg/dL)'}),
            'ldl': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'LDL (mg/dL)'}),
            'hdl': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'HDL (mg/dL)'}),
            'fbs': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'FBS (mg/dL)'}),
            'triglycerides': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'Triglycerides (mg/dL)'}),
            'bmi': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'BMI'}),
            'fat_percent': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'เปอร์เซ็นต์ไขมัน'}),
            'visceral_fat': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'ไขมันในช่องท้อง'}),
            'muscle_percent': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'placeholder': 'เปอร์เซ็นต์กล้ามเนื้อ'}),
            'bmr': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'อัตราการเผาผลาญ BMR'}),
            'body_age': forms.NumberInput(attrs={'class': 'form-control', 'placeholder': 'อายุร่างกาย'}),
            'recorded_at': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['recorded_at'].input_formats = ['%Y-%m-%dT%H:%M']


class DateRangeFilterForm(forms.Form):
    """Form for filtering records by date range"""
    date_start = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        label='วันที่เริ่มต้น'
    )
    date_end = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        label='วันที่สิ้นสุด'
    )


class HealthIndicatorReportForm(forms.Form):
    """Form for health indicator report filtering"""
    
    HEALTH_INDICATOR_CHOICES = [
        ('bmi', 'BMI'),
        ('blood_pressure_systolic', 'ความดันโลหิตตัวบน (Systolic)'),
        ('blood_pressure_diastolic', 'ความดันโลหิตตัวล่าง (Diastolic)'),
        ('fat_percent', 'เปอร์เซ็นต์ไขมัน'),
        ('visceral_fat', 'ไขมันในช่องท้อง'),
        ('muscle_percent', 'เปอร์เซ็นต์กล้ามเนื้อ'),
        ('waist', 'เส้นรอบเอว (cm)'),
        ('cholesterol', 'คอเลสเตอรอล (mg/dL)'),
        ('ldl', 'LDL (mg/dL)'),
        ('hdl', 'HDL (mg/dL)'),
        ('fbs', 'น้ำตาลในเลือด FBS (mg/dL)'),
        ('triglycerides', 'ไตรกลีเซอไรด์ (mg/dL)'),
        ('height', 'ส่วนสูง (cm)'),
        ('weight', 'น้ำหนัก (kg)'),
        ('bmr', 'อัตราการเผาผลาญ BMR'),
        ('body_age', 'อายุร่างกาย'),
    ]
    
    health_indicator = forms.ChoiceField(
        choices=HEALTH_INDICATOR_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='ตัวชี้วัดสุขภาพ'
    )
    
    min_value = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        widget=forms.NumberInput(attrs={
            'class': 'form-control', 
            'placeholder': 'ค่าต่ำสุด',
            'step': '0.01'
        }),
        label='ค่าต่ำสุด'
    )
    
    max_value = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        widget=forms.NumberInput(attrs={
            'class': 'form-control', 
            'placeholder': 'ค่าสูงสุด',
            'step': '0.01'
        }),
        label='ค่าสูงสุด'
    )
    
    include_latest_only = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label='แสดงเฉพาะข้อมูลล่าสุดของแต่ละบุคคล'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        min_value = cleaned_data.get('min_value')
        max_value = cleaned_data.get('max_value')
        
        if min_value and max_value and min_value >= max_value:
            raise forms.ValidationError("ค่าต่ำสุดต้องน้อยกว่าค่าสูงสุด")
        
        return cleaned_data


class HealthStatusReportForm(forms.Form):
    """Form for health status report (Normal/Abnormal categorization)"""
    
    HEALTH_INDICATOR_CHOICES = [
        ('bmi', 'BMI'),
        ('blood_pressure', 'ความดันโลหิต'),
        ('fat_percent', 'เปอร์เซ็นต์ไขมัน'),
        ('visceral_fat', 'ไขมันในช่องท้อง'),
        ('muscle_percent', 'เปอร์เซ็นต์กล้ามเนื้อ'),
        ('waist', 'เส้นรอบเอว'),
        ('cholesterol', 'คอเลสเตอรอล'),
        ('ldl', 'LDL'),
        ('hdl', 'HDL'),
        ('fbs', 'น้ำตาลในเลือด (FBS)'),
        ('triglycerides', 'ไตรกลีเซอไรด์'),
    ]
    
    STATUS_FILTER_CHOICES = [
        ('all', 'ทั้งหมด'),
        ('normal', 'ปกติ'),
        ('abnormal', 'ผิดปกติ'),
    ]
    
    health_indicator = forms.ChoiceField(
        choices=HEALTH_INDICATOR_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='ตัวชี้วัดสุขภาพ'
    )
    
    status_filter = forms.ChoiceField(
        choices=STATUS_FILTER_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='กรองตามสถานะ',
        initial='all'
    )
    
    include_latest_only = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label='แสดงเฉพาะข้อมูลล่าสุดของแต่ละบุคคล'
    )


class AdminHealthReportForm(forms.Form):
    """Comprehensive admin form for health reports with advanced search and filtering"""
    
    GENDER_CHOICES = [
        ('', 'ทั้งหมด'),
        ('male', 'ชาย'),
        ('female', 'หญิง'),
    ]
    
    HEALTH_INDEX_CHOICES = [
        ('bmi', 'BMI'),
        ('blood_pressure', 'ความดันโลหิต'),
        ('fat_percent', 'เปอร์เซ็นต์ไขมัน'),
        ('visceral_fat', 'ไขมันในช่องท้อง'),
        ('muscle_percent', 'เปอร์เซ็นต์กล้ามเนื้อ'),
        ('waist', 'เส้นรอบเอว'),
        ('cholesterol', 'คอเลสเตอรอล'),
        ('ldl', 'LDL'),
        ('hdl', 'HDL'),
        ('fbs', 'น้ำตาลในเลือด (FBS)'),
        ('triglycerides', 'ไตรกลีเซอไรด์'),
    ]
    
    # Search filters
    firstname = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'ค้นหาชื่อ'
        }),
        label='ชื่อ'
    )
    
    lastname = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'ค้นหานามสกุล'
        }),
        label='นามสกุล'
    )
    
    gender = forms.ChoiceField(
        required=False,
        choices=GENDER_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='เพศ'
    )
    
    age_min = forms.IntegerField(
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'อายุต่ำสุด',
            'min': '1',
            'max': '120'
        }),
        label='อายุต่ำสุด'
    )
    
    age_max = forms.IntegerField(
        required=False,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'อายุสูงสุด',
            'min': '1',
            'max': '120'
        }),
        label='อายุสูงสุด'
    )
    
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        }),
        label='วันที่เริ่มต้น'
    )
    
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        }),
        label='วันที่สิ้นสุด'
    )
    
    # Health index for graphs
    health_index = forms.ChoiceField(
        choices=HEALTH_INDEX_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label='ตัวชี้วัดสุขภาพสำหรับกราฟ',
        initial='bmi'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        age_min = cleaned_data.get('age_min')
        age_max = cleaned_data.get('age_max')
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')
        
        if age_min and age_max and age_min >= age_max:
            raise forms.ValidationError("อายุต่ำสุดต้องน้อยกว่าอายุสูงสุด")
        
        if date_from and date_to and date_from >= date_to:
            raise forms.ValidationError("วันที่เริ่มต้นต้องน้อยกว่าวันที่สิ้นสุด")
        
        return cleaned_data
