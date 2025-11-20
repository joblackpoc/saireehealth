"""
Advanced Injection Attack Prevention System for HealthProgress
Multi-Vector Protection: SQL, LDAP, XPath, XSLT, LaTeX, Template, Code Injection
Expert Blue Team Implementation - ETH Standards
"""
import re
import json
import ast
import html
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Union
from django.utils.html import escape
from django.core.exceptions import SuspiciousOperation
from .security_core import SecurityLogger


class SQLInjectionPrevention:
    """
    Advanced SQL Injection prevention with multi-database support
    """
    
    def __init__(self):
        self.sql_patterns = self._compile_sql_patterns()
        self.dangerous_functions = {
            'exec', 'execute', 'eval', 'system', 'shell_exec',
            'passthru', 'proc_open', 'popen', 'file_get_contents',
            'include', 'require', 'include_once', 'require_once'
        }
        
    def _compile_sql_patterns(self) -> List[re.Pattern]:
        """
        Compile comprehensive SQL injection patterns
        """
        patterns = [
            # Basic SQL injection patterns
            re.compile(r'(\bUNION\b.*\bSELECT\b)', re.IGNORECASE),
            re.compile(r'(\bSELECT\b.*\bFROM\b.*\bWHERE\b.*[\'"]?\s*=\s*[\'"]?)', re.IGNORECASE),
            re.compile(r'(\bINSERT\b.*\bINTO\b.*\bVALUES\b)', re.IGNORECASE),
            re.compile(r'(\bUPDATE\b.*\bSET\b.*\bWHERE\b)', re.IGNORECASE),
            re.compile(r'(\bDELETE\b.*\bFROM\b.*\bWHERE\b)', re.IGNORECASE),
            re.compile(r'(\bDROP\b.*\bTABLE\b)', re.IGNORECASE),
            re.compile(r'(\bCREATE\b.*\bTABLE\b)', re.IGNORECASE),
            re.compile(r'(\bALTER\b.*\bTABLE\b)', re.IGNORECASE),
            
            # Advanced SQL injection techniques
            re.compile(r'(\bEXEC\b.*\bxp_cmdshell\b)', re.IGNORECASE),
            re.compile(r'(\bSP_EXECUTESQL\b)', re.IGNORECASE),
            re.compile(r'(\bBULK\b.*\bINSERT\b)', re.IGNORECASE),
            re.compile(r'(\bOPENROWSET\b)', re.IGNORECASE),
            re.compile(r'(\bOPENQUERY\b)', re.IGNORECASE),
            
            # Boolean-based blind injection
            re.compile(r'(AND\s+\d+\s*=\s*\d+)', re.IGNORECASE),
            re.compile(r'(OR\s+\d+\s*=\s*\d+)', re.IGNORECASE),
            re.compile(r'(\'\s*OR\s*\'1\'\s*=\s*\'1)', re.IGNORECASE),
            re.compile(r'(\'\s*OR\s*1\s*=\s*1\s*--)', re.IGNORECASE),
            re.compile(r'(\'\s*UNION\s*SELECT\s*NULL)', re.IGNORECASE),
            
            # Time-based blind injection
            re.compile(r'(\bWAITFOR\b.*\bDELAY\b)', re.IGNORECASE),
            re.compile(r'(\bSLEEP\b\s*\(\s*\d+\s*\))', re.IGNORECASE),
            re.compile(r'(\bBENCHMARK\b\s*\()', re.IGNORECASE),
            re.compile(r'(\bPG_SLEEP\b\s*\(\s*\d+\s*\))', re.IGNORECASE),
            
            # Database-specific functions
            re.compile(r'(\bVERSION\b\s*\(\s*\))', re.IGNORECASE),
            re.compile(r'(\bUSER\b\s*\(\s*\))', re.IGNORECASE),
            re.compile(r'(\bDATABASE\b\s*\(\s*\))', re.IGNORECASE),
            re.compile(r'(\bSCHEMA\b\s*\(\s*\))', re.IGNORECASE),
            re.compile(r'(\b@@VERSION\b)', re.IGNORECASE),
            re.compile(r'(\b@@SERVERNAME\b)', re.IGNORECASE),
            
            # SQL comments and terminators
            re.compile(r'(/\*.*?\*/)', re.DOTALL),
            re.compile(r'(--.*$)', re.MULTILINE),
            re.compile(r'(#.*$)', re.MULTILINE),
            re.compile(r'(;\s*$)', re.MULTILINE),
            
            # Encoded injection attempts
            re.compile(r'(%27|%22|%2D%2D|%23)', re.IGNORECASE),  # URL encoded
            re.compile(r'(&#x27;|&#x22;|&#39;|&#34;)', re.IGNORECASE),  # HTML entity encoded
        ]
        
        return patterns
    
    def detect_sql_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect SQL injection attempts in input data
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'sql_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        # Convert input to string for analysis
        if isinstance(input_data, (dict, list)):
            text_data = json.dumps(input_data)
        else:
            text_data = str(input_data)
        
        # URL decode the input
        try:
            decoded_data = urllib.parse.unquote(text_data)
            text_data = text_data + " " + decoded_data  # Check both encoded and decoded
        except Exception:
            pass
        
        # Check against SQL patterns
        for pattern in self.sql_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 20
                detection_result['detected_patterns'].extend(matches)
        
        # Additional heuristic checks
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'UNION']
        keyword_count = sum(1 for keyword in sql_keywords if keyword.upper() in text_data.upper())
        
        if keyword_count >= 2:
            detection_result['is_malicious'] = True
            detection_result['risk_score'] += keyword_count * 15
            detection_result['detected_patterns'].append(f'Multiple SQL keywords: {keyword_count}')
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 2)
        
        return detection_result
    
    def sanitize_sql_input(self, input_data: str) -> str:
        """
        Sanitize input to prevent SQL injection
        """
        if not input_data:
            return input_data
        
        # Remove or escape dangerous characters
        sanitized = input_data.replace("'", "''")  # Escape single quotes
        sanitized = re.sub(r'[;\-\-#/\*\*/]', '', sanitized)  # Remove SQL terminators and comments
        sanitized = re.sub(r'\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b', 
                          lambda m: f'[{m.group(0)}]', sanitized, flags=re.IGNORECASE)
        
        return sanitized


class LDAPInjectionPrevention:
    """
    LDAP Injection prevention system
    """
    
    def __init__(self):
        self.ldap_patterns = self._compile_ldap_patterns()
    
    def _compile_ldap_patterns(self) -> List[re.Pattern]:
        """
        Compile LDAP injection patterns
        """
        return [
            # LDAP filter injection
            re.compile(r'(\(\|.*\))', re.IGNORECASE),  # OR filters
            re.compile(r'(\(&.*\))', re.IGNORECASE),   # AND filters
            re.compile(r'(\(!\w+=.*\))', re.IGNORECASE),  # NOT filters
            re.compile(r'(\*\)\(\w+=.*)', re.IGNORECASE),  # Wildcard bypass
            re.compile(r'(\)\(\w+=\*)'), # Attribute wildcards
            
            # LDAP attribute manipulation
            re.compile(r'(objectClass=\*)', re.IGNORECASE),
            re.compile(r'(cn=\*)', re.IGNORECASE),
            re.compile(r'(uid=\*)', re.IGNORECASE),
            re.compile(r'(sn=\*)', re.IGNORECASE),
            
            # LDAP escape sequence abuse
            re.compile(r'(\\[0-9a-fA-F]{2})'),  # Hex escapes
            re.compile(r'(\\\*|\\\(|\\\)|\\\\)'),  # Special character escapes
        ]
    
    def detect_ldap_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect LDAP injection attempts
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'ldap_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        text_data = str(input_data)
        
        # Check LDAP patterns
        for pattern in self.ldap_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 25
                detection_result['detected_patterns'].extend(matches)
        
        # Check for LDAP filter characteristics
        if '(' in text_data and ')' in text_data:
            # Count parentheses balance
            open_count = text_data.count('(')
            close_count = text_data.count(')')
            if abs(open_count - close_count) > 0:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 20
                detection_result['detected_patterns'].append('Unbalanced LDAP filter parentheses')
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 1.5)
        
        return detection_result
    
    def sanitize_ldap_input(self, input_data: str) -> str:
        """
        Sanitize LDAP input
        """
        if not input_data:
            return input_data
        
        # LDAP special characters that need escaping
        ldap_escapes = {
            '(': '\\28',
            ')': '\\29',
            '\\': '\\5c',
            '*': '\\2a',
            '/': '\\2f',
            '\x00': '\\00'
        }
        
        sanitized = input_data
        for char, escape in ldap_escapes.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized


class XPathInjectionPrevention:
    """
    XPath Injection prevention system
    """
    
    def __init__(self):
        self.xpath_patterns = self._compile_xpath_patterns()
    
    def _compile_xpath_patterns(self) -> List[re.Pattern]:
        """
        Compile XPath injection patterns
        """
        return [
            # Basic XPath injection
            re.compile(r'(\'.*or.*\'.*=.*\')', re.IGNORECASE),
            re.compile(r'(\".*or.*\".*=.*\")', re.IGNORECASE),
            re.compile(r'(\]\s*\[\s*)', re.IGNORECASE),  # Array access
            
            # XPath functions
            re.compile(r'(\bcount\s*\(\s*/\s*\))', re.IGNORECASE),
            re.compile(r'(\bstring-length\s*\()', re.IGNORECASE),
            re.compile(r'(\bsubstring\s*\()', re.IGNORECASE),
            re.compile(r'(\bstarts-with\s*\()', re.IGNORECASE),
            re.compile(r'(\bcontains\s*\()', re.IGNORECASE),
            re.compile(r'(\bnormalize-space\s*\()', re.IGNORECASE),
            
            # XPath axis
            re.compile(r'(//@\w+)', re.IGNORECASE),  # Attribute axis
            re.compile(r'(//\w+)', re.IGNORECASE),   # Descendant axis
            re.compile(r'(\.\./)', re.IGNORECASE),    # Parent axis
            
            # XPath operators
            re.compile(r'(\bor\b|\band\b|\bnot\b)', re.IGNORECASE),
            re.compile(r'(!=|<=|>=|<|>)'),
            
            # XPath comments
            re.compile(r'(/\*.*?\*/)', re.DOTALL),
        ]
    
    def detect_xpath_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect XPath injection attempts
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'xpath_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        text_data = str(input_data)
        
        # Check XPath patterns
        for pattern in self.xpath_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 20
                detection_result['detected_patterns'].extend(matches)
        
        # Check for XPath characteristics
        xpath_indicators = ['/', '@', '[', ']', 'position()', 'last()', 'text()']
        indicator_count = sum(1 for indicator in xpath_indicators if indicator in text_data)
        
        if indicator_count >= 2:
            detection_result['is_malicious'] = True
            detection_result['risk_score'] += indicator_count * 10
            detection_result['detected_patterns'].append(f'Multiple XPath indicators: {indicator_count}')
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 1.8)
        
        return detection_result


class XSLTInjectionPrevention:
    """
    XSLT Injection prevention system
    """
    
    def __init__(self):
        self.xslt_patterns = self._compile_xslt_patterns()
    
    def _compile_xslt_patterns(self) -> List[re.Pattern]:
        """
        Compile XSLT injection patterns
        """
        return [
            # XSLT elements
            re.compile(r'(<xsl:.*>)', re.IGNORECASE),
            re.compile(r'(</?xsl:\w+.*?>)', re.IGNORECASE),
            
            # Dangerous XSLT functions
            re.compile(r'(document\s*\(\s*[\'\"]\w+[\'\"]\s*\))', re.IGNORECASE),
            re.compile(r'(unparsed-text\s*\()', re.IGNORECASE),
            re.compile(r'(system-property\s*\()', re.IGNORECASE),
            re.compile(r'(extension-element-prefixes)', re.IGNORECASE),
            re.compile(r'(exclude-result-prefixes)', re.IGNORECASE),
            
            # XSLT namespace declarations
            re.compile(r'(xmlns:xsl\s*=)', re.IGNORECASE),
            re.compile(r'(xmlns:\w+\s*=)', re.IGNORECASE),
            
            # XSLT processing instructions
            re.compile(r'(<\?xml.*\?>)', re.IGNORECASE),
            re.compile(r'(<xsl:stylesheet.*>)', re.IGNORECASE),
            re.compile(r'(<xsl:transform.*>)', re.IGNORECASE),
        ]
    
    def detect_xslt_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect XSLT injection attempts
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'xslt_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        text_data = str(input_data)
        
        # Check XSLT patterns
        for pattern in self.xslt_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 30
                detection_result['detected_patterns'].extend(matches)
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 1.5)
        
        return detection_result


class LaTeXInjectionPrevention:
    """
    LaTeX Injection prevention system
    """
    
    def __init__(self):
        self.latex_patterns = self._compile_latex_patterns()
    
    def _compile_latex_patterns(self) -> List[re.Pattern]:
        """
        Compile LaTeX injection patterns
        """
        return [
            # Dangerous LaTeX commands
            re.compile(r'(\\input\s*\{)', re.IGNORECASE),
            re.compile(r'(\\include\s*\{)', re.IGNORECASE),
            re.compile(r'(\\write18\s*\{)', re.IGNORECASE),
            re.compile(r'(\\immediate\\write18)', re.IGNORECASE),
            re.compile(r'(\\openin)', re.IGNORECASE),
            re.compile(r'(\\openout)', re.IGNORECASE),
            re.compile(r'(\\read)', re.IGNORECASE),
            re.compile(r'(\\write)', re.IGNORECASE),
            
            # File system access
            re.compile(r'(\\InputIfFileExists)', re.IGNORECASE),
            re.compile(r'(\\IfFileExists)', re.IGNORECASE),
            re.compile(r'(\\@@input)', re.IGNORECASE),
            
            # Category code manipulation
            re.compile(r'(\\catcode)', re.IGNORECASE),
            re.compile(r'(\\makeatletter)', re.IGNORECASE),
            re.compile(r'(\\makeatother)', re.IGNORECASE),
            
            # Primitive TeX commands
            re.compile(r'(\\def\\)', re.IGNORECASE),
            re.compile(r'(\\let\\)', re.IGNORECASE),
            re.compile(r'(\\expandafter)', re.IGNORECASE),
            re.compile(r'(\\csname)', re.IGNORECASE),
            re.compile(r'(\\endcsname)', re.IGNORECASE),
        ]
    
    def detect_latex_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect LaTeX injection attempts
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'latex_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        text_data = str(input_data)
        
        # Check LaTeX patterns
        for pattern in self.latex_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 35
                detection_result['detected_patterns'].extend(matches)
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 1.2)
        
        return detection_result


class TemplateInjectionPrevention:
    """
    Server-Side Template Injection (SSTI) prevention system
    """
    
    def __init__(self):
        self.template_patterns = self._compile_template_patterns()
    
    def _compile_template_patterns(self) -> List[re.Pattern]:
        """
        Compile template injection patterns for various engines
        """
        return [
            # Jinja2/Django template syntax
            re.compile(r'(\{\{.*\}\})', re.DOTALL),
            re.compile(r'(\{%.*%\})', re.DOTALL),
            
            # Twig template syntax
            re.compile(r'(\{\{.*\}\})', re.DOTALL),
            re.compile(r'(\{%.*%\})', re.DOTALL),
            
            # Smarty template syntax
            re.compile(r'(\{.*\})', re.DOTALL),
            
            # Freemarker template syntax
            re.compile(r'(\$\{.*\})', re.DOTALL),
            re.compile(r'(<#.*>)', re.DOTALL),
            re.compile(r'(<@.*>)', re.DOTALL),
            
            # Velocity template syntax
            re.compile(r'(\$\{.*\})', re.DOTALL),
            re.compile(r'(#\{.*\})', re.DOTALL),
            
            # Thymeleaf template syntax
            re.compile(r'(\$\{.*\})', re.DOTALL),
            re.compile(r'(\*\{.*\})', re.DOTALL),
            
            # Dangerous template operations
            re.compile(r'({{.*config.*}})', re.IGNORECASE),
            re.compile(r'({{.*self.*}})', re.IGNORECASE),
            re.compile(r'({{.*request.*}})', re.IGNORECASE),
            re.compile(r'({{.*lipsum.*}})', re.IGNORECASE),
            re.compile(r'({{.*cycler.*}})', re.IGNORECASE),
            re.compile(r'({{.*joiner.*}})', re.IGNORECASE),
            re.compile(r'({{.*namespace.*}})', re.IGNORECASE),
            
            # Python object access in templates
            re.compile(r'(__.*__)', re.IGNORECASE),  # Dunder methods
            re.compile(r'(\..*class.*)', re.IGNORECASE),
            re.compile(r'(\..*mro.*)', re.IGNORECASE),
            re.compile(r'(\..*subclasses.*)', re.IGNORECASE),
            re.compile(r'(\..*globals.*)', re.IGNORECASE),
        ]
    
    def detect_template_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect template injection attempts
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'template_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        text_data = str(input_data)
        
        # Check template patterns
        for pattern in self.template_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 25
                detection_result['detected_patterns'].extend(matches)
        
        # Check for template engine specific indicators
        template_indicators = ['{{', '}}', '{%', '%}', '${', '#{', '<#', '<@']
        indicator_count = sum(1 for indicator in template_indicators if indicator in text_data)
        
        if indicator_count >= 2:
            detection_result['is_malicious'] = True
            detection_result['risk_score'] += indicator_count * 15
            detection_result['detected_patterns'].append(f'Template syntax indicators: {indicator_count}')
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 1.6)
        
        return detection_result


class CodeInjectionPrevention:
    """
    Code Injection prevention system for multiple languages
    """
    
    def __init__(self):
        self.code_patterns = self._compile_code_patterns()
    
    def _compile_code_patterns(self) -> List[re.Pattern]:
        """
        Compile code injection patterns
        """
        return [
            # Python code injection
            re.compile(r'(\beval\s*\()', re.IGNORECASE),
            re.compile(r'(\bexec\s*\()', re.IGNORECASE),
            re.compile(r'(\b__import__\s*\()', re.IGNORECASE),
            re.compile(r'(\bcompile\s*\()', re.IGNORECASE),
            re.compile(r'(\bgetattr\s*\()', re.IGNORECASE),
            re.compile(r'(\bsetattr\s*\()', re.IGNORECASE),
            re.compile(r'(\bdelattr\s*\()', re.IGNORECASE),
            
            # JavaScript code injection
            re.compile(r'(\beval\s*\()', re.IGNORECASE),
            re.compile(r'(\bFunction\s*\()', re.IGNORECASE),
            re.compile(r'(\bsetTimeout\s*\()', re.IGNORECASE),
            re.compile(r'(\bsetInterval\s*\()', re.IGNORECASE),
            re.compile(r'(document\.write)', re.IGNORECASE),
            re.compile(r'(document\.writeln)', re.IGNORECASE),
            re.compile(r'(innerHTML\s*=)', re.IGNORECASE),
            
            # PHP code injection
            re.compile(r'(\beval\s*\()', re.IGNORECASE),
            re.compile(r'(\bassert\s*\()', re.IGNORECASE),
            re.compile(r'(\bsystem\s*\()', re.IGNORECASE),
            re.compile(r'(\bexec\s*\()', re.IGNORECASE),
            re.compile(r'(\bshell_exec\s*\()', re.IGNORECASE),
            re.compile(r'(\bpassthru\s*\()', re.IGNORECASE),
            re.compile(r'(\bproc_open\s*\()', re.IGNORECASE),
            re.compile(r'(\bpopen\s*\()', re.IGNORECASE),
            
            # Ruby code injection
            re.compile(r'(\beval\s*\()', re.IGNORECASE),
            re.compile(r'(\binstance_eval\s*\()', re.IGNORECASE),
            re.compile(r'(\bclass_eval\s*\()', re.IGNORECASE),
            re.compile(r'(\bmodule_eval\s*\()', re.IGNORECASE),
            re.compile(r'(\bsend\s*\()', re.IGNORECASE),
            
            # Operating system command injection
            re.compile(r'(;\s*cat\s+/etc/passwd)', re.IGNORECASE),
            re.compile(r'(;\s*ls\s+-la)', re.IGNORECASE),
            re.compile(r'(&&\s*id)', re.IGNORECASE),
            re.compile(r'(\|\s*whoami)', re.IGNORECASE),
            re.compile(r'(`.*`)', re.IGNORECASE),  # Command substitution
            re.compile(r'(\$\(.*\))', re.IGNORECASE),  # Command substitution
        ]
    
    def detect_code_injection(self, input_data: Any) -> Dict[str, Any]:
        """
        Detect code injection attempts
        """
        detection_result = {
            'is_malicious': False,
            'risk_score': 0,
            'detected_patterns': [],
            'attack_type': 'code_injection',
            'confidence': 0
        }
        
        if not input_data:
            return detection_result
        
        text_data = str(input_data)
        
        # Check code patterns
        for pattern in self.code_patterns:
            matches = pattern.findall(text_data)
            if matches:
                detection_result['is_malicious'] = True
                detection_result['risk_score'] += 30
                detection_result['detected_patterns'].extend(matches)
        
        # Check for Python AST parsing to detect valid Python code
        try:
            ast.parse(text_data)
            # If it parses as valid Python code, increase risk
            detection_result['is_malicious'] = True
            detection_result['risk_score'] += 25
            detection_result['detected_patterns'].append('Valid Python code detected')
        except (SyntaxError, ValueError):
            # Not valid Python code, which is good
            pass
        
        # Calculate confidence
        if detection_result['risk_score'] > 0:
            detection_result['confidence'] = min(100, detection_result['risk_score'] * 1.4)
        
        return detection_result


class MultiVectorInjectionDetector:
    """
    Unified multi-vector injection detection system
    """
    
    def __init__(self):
        self.detectors = {
            'sql': SQLInjectionPrevention(),
            'ldap': LDAPInjectionPrevention(),
            'xpath': XPathInjectionPrevention(),
            'xslt': XSLTInjectionPrevention(),
            'latex': LaTeXInjectionPrevention(),
            'template': TemplateInjectionPrevention(),
            'code': CodeInjectionPrevention()
        }
    
    def comprehensive_injection_scan(self, input_data: Any, context: str = 'general') -> Dict[str, Any]:
        """
        Perform comprehensive injection detection across all vectors
        """
        scan_results = {
            'overall_malicious': False,
            'total_risk_score': 0,
            'detected_attacks': [],
            'highest_confidence': 0,
            'scan_context': context,
            'input_hash': hash(str(input_data)) if input_data else 0
        }
        
        # Run all detectors
        for detector_name, detector in self.detectors.items():
            try:
                method_name = f'detect_{detector_name}_injection'
                if hasattr(detector, method_name):
                    result = getattr(detector, method_name)(input_data)
                    
                    if result['is_malicious']:
                        scan_results['overall_malicious'] = True
                        scan_results['total_risk_score'] += result['risk_score']
                        scan_results['detected_attacks'].append({
                            'type': result['attack_type'],
                            'risk_score': result['risk_score'],
                            'confidence': result['confidence'],
                            'patterns': result['detected_patterns']
                        })
                        
                        # Track highest confidence
                        if result['confidence'] > scan_results['highest_confidence']:
                            scan_results['highest_confidence'] = result['confidence']
                            
            except Exception as e:
                SecurityLogger.log_security_event(
                    'injection_detector_error',
                    'medium',
                    {
                        'detector': detector_name,
                        'error': str(e),
                        'context': context
                    }
                )
        
        # Log comprehensive results if threats detected
        if scan_results['overall_malicious']:
            SecurityLogger.log_security_event(
                'multi_vector_injection_detected',
                'high' if scan_results['total_risk_score'] > 100 else 'medium',
                scan_results
            )
        
        return scan_results
    
    def sanitize_input(self, input_data: Any, attack_types: List[str] = None) -> str:
        """
        Sanitize input against specific attack types
        """
        if not input_data:
            return input_data
        
        sanitized_data = str(input_data)
        
        # Default to all sanitization if not specified
        if not attack_types:
            attack_types = ['sql', 'ldap', 'xpath', 'xslt', 'latex', 'template', 'code']
        
        for attack_type in attack_types:
            if attack_type in self.detectors:
                detector = self.detectors[attack_type]
                method_name = f'sanitize_{attack_type}_input'
                
                if hasattr(detector, method_name):
                    try:
                        sanitized_data = getattr(detector, method_name)(sanitized_data)
                    except Exception as e:
                        SecurityLogger.log_security_event(
                            'sanitization_error',
                            'medium',
                            {
                                'attack_type': attack_type,
                                'error': str(e)
                            }
                        )
        
        return sanitized_data
    
    def generate_injection_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate human-readable injection scan report
        """
        if not scan_results['overall_malicious']:
            return "✅ No injection attacks detected - Input appears safe"
        
        report_lines = [
            f"🚨 INJECTION ATTACK DETECTED",
            f"Total Risk Score: {scan_results['total_risk_score']}",
            f"Highest Confidence: {scan_results['highest_confidence']}%",
            f"Context: {scan_results['scan_context']}",
            "",
            "Detected Attack Vectors:"
        ]
        
        for attack in scan_results['detected_attacks']:
            report_lines.extend([
                f"  • {attack['type'].upper()}",
                f"    Risk Score: {attack['risk_score']}",
                f"    Confidence: {attack['confidence']}%",
                f"    Patterns: {', '.join(attack['patterns'][:3])}{'...' if len(attack['patterns']) > 3 else ''}",
                ""
            ])
        
        return "\n".join(report_lines)