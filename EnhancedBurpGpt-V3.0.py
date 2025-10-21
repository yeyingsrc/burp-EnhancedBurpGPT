# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IScannerCheck
from burp import ITab
from javax.swing import JMenuItem, JPanel, JTextArea, JScrollPane, BoxLayout, JTabbedPane, JDialog, JProgressBar, JLabel
from javax.swing import JButton, JTextField, JOptionPane, JSplitPane, JCheckBox, JComboBox
from java.awt import BorderLayout, Dimension, Color
from java.io import PrintWriter
from java.util import ArrayList
import json
import urllib2
import ssl
from javax.swing import SwingUtilities
from java.lang import Thread, Runnable, String, System
from java.util.concurrent import TimeUnit, Future, TimeoutException
from java.util.concurrent import ExecutorService, Executors
import java.text
from java.io import ByteArrayOutputStream, OutputStreamWriter
from java.nio.charset import StandardCharsets
import base64
from javax.swing import DefaultListModel, JList
from javax.swing.event import ListSelectionListener
from javax.swing import BorderFactory, Box
from java.awt import GridBagLayout, GridBagConstraints, Insets
from abc import ABCMeta, abstractmethod

# ============================================================================
# Logging System
# ============================================================================

class LogLevel:
    """Log level constants"""
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    
    @staticmethod
    def to_string(level):
        """Convert log level to string"""
        levels = ["DEBUG", "INFO", "WARN", "ERROR"]
        if 0 <= level < len(levels):
            return levels[level]
        return "UNKNOWN"
    
    @staticmethod
    def to_color(level):
        """Get color for log level"""
        colors = {
            LogLevel.DEBUG: Color(128, 128, 128),  # Gray
            LogLevel.INFO: Color(0, 128, 0),       # Green
            LogLevel.WARN: Color(255, 165, 0),     # Orange
            LogLevel.ERROR: Color(255, 0, 0)       # Red
        }
        return colors.get(level, Color.BLACK)


class Logger:
    """Enhanced logging system with levels and formatting"""
    
    def __init__(self, log_area, stdout):
        self.log_area = log_area
        self.stdout = stdout
        self.log_level = LogLevel.INFO
        self.max_lines = 1000
        self.line_count = 0
        
    def set_log_level(self, level):
        """Set minimum log level to display"""
        self.log_level = level
        
    def log(self, message, level=LogLevel.INFO):
        """Log message with specified level"""
        if level < self.log_level:
            return
        
        # Format timestamp
        timestamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(java.util.Date())
        level_str = LogLevel.to_string(level)
        formatted = "[{}] [{}] {}".format(timestamp, level_str, message)
        
        # Output to stdout
        self.stdout.println(formatted)
        
        # Output to UI with auto-truncation
        if hasattr(self, 'log_area') and self.log_area:
            self._append_to_log_area(formatted)
    
    def _append_to_log_area(self, message):
        """Append message to log area with auto-truncation"""
        def append():
            try:
                self.log_area.append(message + "\n")
                self.line_count += 1
                
                # Auto-truncate if exceeds max lines
                if self.line_count > self.max_lines:
                    text = self.log_area.getText()
                    lines = text.split("\n")
                    # Keep only the last max_lines
                    truncated = "\n".join(lines[-self.max_lines:])
                    self.log_area.setText(truncated)
                    self.line_count = self.max_lines
                
                # Auto-scroll to bottom
                self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
            except Exception as e:
                self.stdout.println("[-] Error appending to log area: {}".format(str(e)))
        
        SwingUtilities.invokeLater(append)
    
    def debug(self, message):
        """Log debug message"""
        self.log(message, LogLevel.DEBUG)
    
    def info(self, message):
        """Log info message"""
        self.log(message, LogLevel.INFO)
    
    def warn(self, message):
        """Log warning message"""
        self.log(message, LogLevel.WARN)
    
    def error(self, message):
        """Log error message"""
        self.log(message, LogLevel.ERROR)
    
    def clear(self):
        """Clear log area"""
        if hasattr(self, 'log_area') and self.log_area:
            SwingUtilities.invokeLater(lambda: self.log_area.setText(""))
            self.line_count = 0

# ============================================================================
# Content Truncation Utilities
# ============================================================================

class ContentTruncator:
    """Smart content truncation that preserves structure"""
    
    @staticmethod
    def smart_truncate(content, max_length, content_name="content"):
        """
        Intelligently truncate content while preserving structure
        
        Args:
            content: Content to truncate
            max_length: Maximum allowed length
            content_name: Name for logging purposes
            
        Returns:
            Truncated content with notification
        """
        if not content:
            return ""
        
        # Convert to string if needed
        if isinstance(content, (bytes, bytearray)):
            try:
                content = content.decode('utf-8', errors='ignore')
            except:
                content = str(content)
        else:
            content = str(content)
        
        original_length = len(content)
        
        # No truncation needed
        if original_length <= max_length:
            return content
        
        # Try to preserve HTTP structure (headers + partial body)
        headers_end = content.find("\r\n\r\n")
        if headers_end != -1:
            headers = content[:headers_end + 4]
            body = content[headers_end + 4:]
            
            # Calculate space for body
            header_size = len(headers)
            truncation_marker = "\n\n[!!! CONTENT TRUNCATED !!!]\n[Original size: {} chars, showing first {} chars of body]\n[Configure 'Max Request/Response Length' in settings to show more]\n\n".format(
                original_length, 
                max_length - header_size - 200
            )
            
            available_body_space = max_length - header_size - len(truncation_marker)
            
            if available_body_space > 100:
                # Keep beginning and end of body
                keep_size = available_body_space // 2
                truncated_body = body[:keep_size] + "\n\n... [middle content omitted] ...\n\n" + body[-keep_size:]
                
                return headers + truncation_marker + truncated_body
            else:
                # Not enough space, just truncate body start
                return headers + truncation_marker + body[:available_body_space]
        
        # No HTTP structure detected, simple truncation with markers
        keep_size = (max_length - 200) // 2
        truncation_marker = "\n\n[!!! CONTENT TRUNCATED !!!]\n[Original size: {} chars, showing first and last {} chars]\n[Configure 'Max Request/Response Length' in settings to show more]\n\n".format(
            original_length,
            keep_size
        )
        
        return content[:keep_size] + truncation_marker + content[-keep_size:]
    
    @staticmethod
    def truncate_with_marker(content, max_length):
        """Simple truncation with a clear marker"""
        if not content or len(content) <= max_length:
            return content
        
        original_length = len(content)
        marker = "\n\n[!!! TRUNCATED - Original length: {} chars !!!]\n".format(original_length)
        usable_length = max_length - len(marker)
        
        return content[:usable_length] + marker

# ============================================================================
# SSL Context Handler
# ============================================================================

class TrustAllSSLContext:
    def __init__(self):
        pass
        
    @staticmethod
    def create():
        trust_all_context = ssl.create_default_context()
        trust_all_context.check_hostname = False
        trust_all_context.verify_mode = ssl.CERT_NONE
        return trust_all_context

# ============================================================================
# Multi-Provider API Adapter Architecture
# ============================================================================

class APIProvider:
    """Abstract base class for API providers"""
    __metaclass__ = ABCMeta
    
    def __init__(self, api_key, api_url, model, timeout=60):
        self.api_key = api_key
        self.api_url = api_url
        self.model = model
        self.timeout = timeout
        self.disable_ssl = False
        self.log_callback = None
        # Proxy settings
        self.proxy_enabled = False
        self.proxy_type = "HTTP"
        self.proxy_host = ""
        self.proxy_port = ""
        self.proxy_username = ""
        self.proxy_password = ""
    
    def set_proxy(self, proxy_type, host, port, username="", password=""):
        """Configure proxy settings"""
        self.proxy_enabled = True
        self.proxy_type = proxy_type.upper()
        self.proxy_host = host
        self.proxy_port = port
        self.proxy_username = username
        self.proxy_password = password
        self.log("[+] Proxy configured: {}://{}:{}".format(proxy_type, host, port))
        
        # CRITICAL: Set Java proxy properties immediately for SOCKS5
        if self.proxy_type == "SOCKS5":
            self._setup_java_proxy()
    
    def _setup_java_proxy(self):
        """Setup Java system properties for SOCKS5 proxy"""
        try:
            System.setProperty("socksProxyHost", self.proxy_host)
            System.setProperty("socksProxyPort", str(self.proxy_port))
            
            if self.proxy_username and self.proxy_password:
                System.setProperty("java.net.socks.username", self.proxy_username)
                System.setProperty("java.net.socks.password", self.proxy_password)
            
            self.log("[+] Java SOCKS5 proxy properties set: {}:{}".format(self.proxy_host, self.proxy_port))
        except Exception as e:
            self.log("[-] Error setting Java proxy properties: {}".format(str(e)))
    
    def _make_request_with_socks_proxy(self, url, data=None, headers=None):
        """Make HTTP request using Java's URLConnection with SOCKS5 proxy"""
        from java.net import URL, Proxy, SocketAddress, InetSocketAddress
        from java.net import Proxy as JavaProxy
        from java.io import InputStreamReader, BufferedReader
        
        self.log("[+] Using Java URLConnection with SOCKS5 proxy: {}:{}".format(self.proxy_host, self.proxy_port))
        
        try:
            # Create SOCKS proxy
            sock_addr = InetSocketAddress(self.proxy_host, int(self.proxy_port))
            proxy = JavaProxy(JavaProxy.Type.SOCKS, sock_addr)
            
            # Create URL connection
            java_url = URL(url)
            conn = java_url.openConnection(proxy)
            
            # Set headers
            if headers:
                for key, value in headers.items():
                    conn.setRequestProperty(key, value)
            
            # Set timeout
            conn.setConnectTimeout(int(self.timeout * 1000))
            conn.setReadTimeout(int(self.timeout * 1000))
            
            # Send data if POST
            if data:
                conn.setDoOutput(True)
                conn.setRequestMethod("POST")
                out = conn.getOutputStream()
                out.write(data)
                out.close()
            
            # Get response
            response_code = conn.getResponseCode()
            if response_code >= 400:
                self.log("[-] HTTP Error {}: {}".format(response_code, conn.getResponseMessage()))
                raise Exception("HTTP Error {}: {}".format(response_code, conn.getResponseMessage()))
            
            # Read response body
            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            response_text = ""
            line = reader.readLine()
            while line is not None:
                response_text += line
                line = reader.readLine()
            reader.close()
            
            return response_text
            
        except Exception as e:
            self.log("[-] SOCKS5 proxy error: {}".format(str(e)))
            raise Exception("SOCKS5 proxy error: {}".format(str(e)))
    
    def _create_proxy_opener(self):
        """Create urllib2 opener with proxy support"""
        if not self.proxy_enabled:
            return None
        
        # For HTTP/HTTPS, use urllib2.ProxyHandler
        proxy_protocol = self.proxy_type.lower()
        
        # Build proxy URL
        if self.proxy_username and self.proxy_password:
            proxy_url = "{}://{}:{}@{}:{}".format(
                proxy_protocol,
                self.proxy_username,
                self.proxy_password,
                self.proxy_host,
                self.proxy_port
            )
        else:
            proxy_url = "{}://{}:{}".format(
                proxy_protocol,
                self.proxy_host,
                self.proxy_port
            )
        
        self.log("[+] Using {} proxy: {}:{}".format(proxy_protocol.upper(), self.proxy_host, self.proxy_port))
        
        # Create proxy handler
        proxy_handler = urllib2.ProxyHandler({
            'http': proxy_url,
            'https': proxy_url
        })
        
        if self.disable_ssl:
            ssl_context = TrustAllSSLContext.create()
            https_handler = urllib2.HTTPSHandler(context=ssl_context)
            return urllib2.build_opener(proxy_handler, https_handler)
        else:
            return urllib2.build_opener(proxy_handler)
    
    def set_log_callback(self, callback):
        """Set logging callback function"""
        self.log_callback = callback
    
    def log(self, message):
        """Log message if callback is set"""
        if self.log_callback:
            self.log_callback(message)
    
    @abstractmethod
    def build_request_data(self, prompt, max_tokens):
        """Build request data - format differs per provider"""
        pass
    
    @abstractmethod
    def build_headers(self):
        """Build request headers - authentication differs per provider"""
        pass
    
    @abstractmethod
    def parse_response(self, response_data):
        """Parse response data - format differs per provider"""
        pass
    
    @abstractmethod
    def get_models_url(self):
        """Get models list URL - differs per provider"""
        pass
    
    def send_request(self, prompt, max_tokens):
        """Common request sending flow"""
        try:
            data = self.build_request_data(prompt, max_tokens)
            json_data = json.dumps(data).encode('utf-8')
            
            headers = self.build_headers()
            
            # CRITICAL: Use Java URLConnection for SOCKS5, urllib2 for HTTP/HTTPS
            if self.proxy_enabled and self.proxy_type == "SOCKS5":
                response_text = self._make_request_with_socks_proxy(self.api_url, json_data, headers)
                result = json.loads(response_text)
                return self.parse_response(result)
            
            request = urllib2.Request(url=self.api_url, data=json_data, headers=headers)
            
            # Use proxy if configured
            opener = self._create_proxy_opener()
            if opener:
                response = opener.open(request, timeout=self.timeout)
            elif self.disable_ssl:
                self.log("[*] SSL certificate validation is disabled")
                ssl_context = TrustAllSSLContext.create()
                response = urllib2.urlopen(request, context=ssl_context, timeout=self.timeout)
            else:
                response = urllib2.urlopen(request, timeout=self.timeout)
            
            response_data = response.read()
            response_text = str(response_data)
            result = json.loads(response_text)
            
            return self.parse_response(result)
            
        except Exception as e:
            raise Exception("Error calling {} API: {}".format(self.__class__.__name__, str(e)))
    
    def fetch_models(self):
        """Fetch available models list"""
        try:
            models_url = self.get_models_url()
            if not models_url:
                return self.get_default_models()
            
            # CRITICAL: Use Java URLConnection for SOCKS5, urllib2 for HTTP/HTTPS
            if self.proxy_enabled and self.proxy_type == "SOCKS5":
                headers = self.build_headers()
                response_text = self._make_request_with_socks_proxy(models_url, None, headers)
                result = json.loads(response_text)
                return self.parse_models_response(result)
            
            # 使用完整的认证头来获取模型列表
            headers = self.build_headers()
            request = urllib2.Request(url=models_url, headers=headers)
            
            # Use proxy if configured
            opener = self._create_proxy_opener()
            if opener:
                response = opener.open(request, timeout=self.timeout)
            elif self.disable_ssl:
                ssl_context = TrustAllSSLContext.create()
                response = urllib2.urlopen(request, context=ssl_context, timeout=self.timeout)
            else:
                response = urllib2.urlopen(request, timeout=self.timeout)
            
            response_data = response.read()
            response_text = str(response_data)
            result = json.loads(response_text)
            
            return self.parse_models_response(result)
            
        except Exception as e:
            self.log("[-] Error fetching models: {}".format(str(e)))
            return self.get_default_models()
    
    @abstractmethod
    def parse_models_response(self, response_data):
        """Parse models list response"""
        pass
    
    @abstractmethod
    def get_default_models(self):
        """Get default models list if fetch fails"""
        pass


class OpenAIProvider(APIProvider):
    """OpenAI-compatible API provider (OpenAI, DeepSeek, Ollama, etc.)"""
    
    def build_request_data(self, prompt, max_tokens):
        return {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens
        }
    
    def build_headers(self):
        host = self.api_url.split("://")[-1].split("/")[0]
        return {
            "Host": host,
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.api_key,
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "zh-CN"
        }
    
    def parse_response(self, response_data):
        return {
            "content": response_data["choices"][0]["message"]["content"],
            "usage": response_data.get("usage", {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            })
        }
    
    def get_models_url(self):
        return self.api_url.replace("/v1/chat/completions", "/v1/models")
    
    def parse_models_response(self, response_data):
        if 'data' in response_data:
            return [model.get('id') for model in response_data['data'] if model.get('id')]
        return self.get_default_models()
    
    def get_default_models(self):
        return ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"]


class GeminiProvider(APIProvider):
    """Google Gemini API provider"""
    
    def __init__(self, api_key, model="gemini-pro", timeout=60):
        api_url = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent".format(model)
        super(GeminiProvider, self).__init__(api_key, api_url, model, timeout)
    
    def build_request_data(self, prompt, max_tokens):
        return {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": 0.7
            }
        }
    
    def build_headers(self):
        # Fixed: Removed redundant x-goog-api-key header
        # Gemini API uses URL parameter authentication (?key=...), not header authentication
        return {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    
    def parse_response(self, response_data):
        try:
            content = response_data["candidates"][0]["content"]["parts"][0]["text"]
            usage_metadata = response_data.get("usageMetadata", {})
            
            return {
                "content": content,
                "usage": {
                    "prompt_tokens": usage_metadata.get("promptTokenCount", 0),
                    "completion_tokens": usage_metadata.get("candidatesTokenCount", 0),
                    "total_tokens": usage_metadata.get("totalTokenCount", 0)
                }
            }
        except (KeyError, IndexError) as e:
            raise Exception("Failed to parse Gemini response: {}".format(str(e)))
    
    def send_request(self, prompt, max_tokens):
        """Override to use URL parameter authentication"""
        try:
            url_with_key = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}".format(
                self.model, self.api_key)
            
            data = self.build_request_data(prompt, max_tokens)
            json_data = json.dumps(data).encode('utf-8')
            
            headers = {
                "Content-Type": "application/json",
                "Accept": "*/*",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            
            # CRITICAL: Use Java URLConnection for SOCKS5
            if self.proxy_enabled and self.proxy_type == "SOCKS5":
                response_text = self._make_request_with_socks_proxy(url_with_key, json_data, headers)
                result = json.loads(response_text)
                return self.parse_response(result)
            
            request = urllib2.Request(url=url_with_key, data=json_data, headers=headers)
            
            # Use proxy if configured
            opener = self._create_proxy_opener()
            if opener:
                response = opener.open(request, timeout=self.timeout)
            elif self.disable_ssl:
                ssl_context = TrustAllSSLContext.create()
                response = urllib2.urlopen(request, context=ssl_context, timeout=self.timeout)
            else:
                response = urllib2.urlopen(request, timeout=self.timeout)
            
            response_data = response.read()
            response_text = str(response_data)
            result = json.loads(response_text)
            
            return self.parse_response(result)
            
        except Exception as e:
            raise Exception("Error calling Gemini API: {}".format(str(e)))
    
    def get_models_url(self):
        # Fixed: Added pageSize parameter to support full model list retrieval
        return "https://generativelanguage.googleapis.com/v1beta/models?key={}&pageSize=100".format(self.api_key)
    
    def fetch_models(self):
        """Override fetch_models for Gemini to handle API call differently"""
        try:
            all_models = []
            page_token = None
            
            while True:
                models_url = self.get_models_url()
                
                # Fixed: Added pagination token support
                if page_token:
                    models_url += "&pageToken={}".format(page_token)
                
                self.log("[+] Gemini models URL: {}".format(models_url[:80] + "..."))
                
                # CRITICAL: Use Java URLConnection for SOCKS5
                if self.proxy_enabled and self.proxy_type == "SOCKS5":
                    response_text = self._make_request_with_socks_proxy(models_url, None, {})
                else:
                    # Fixed: Explicitly set request method to GET
                    # Official API requires: GET https://generativelanguage.googleapis.com/v1beta/models
                    request = urllib2.Request(url=models_url)
                    request.get_method = lambda: 'GET'  # Critical fix: Set request method to GET
                    
                    # Use proxy if configured
                    opener = self._create_proxy_opener()
                    if opener:
                        response = opener.open(request, timeout=self.timeout)
                    elif self.disable_ssl:
                        self.log("[*] SSL verification disabled for Gemini")
                        ssl_context = TrustAllSSLContext.create()
                        response = urllib2.urlopen(request, context=ssl_context, timeout=self.timeout)
                    else:
                        response = urllib2.urlopen(request, timeout=self.timeout)
                    
                    response_data = response.read()
                    response_text = str(response_data)
                self.log("[+] Gemini API 响应长度: {} 字节".format(len(response_text)))
                
                result = json.loads(response_text)
                models = self.parse_models_response(result)
                all_models.extend(models)
                
                # Check if there's a next page
                page_token = result.get('nextPageToken')
                if not page_token:
                    break
            
            return all_models if all_models else self.get_default_models()
            
        except urllib2.HTTPError as e:
            self.log("[-] HTTP 错误 {}: {}".format(e.code, str(e)))
            self.log("[*] 使用默认模型列表")
            return self.get_default_models()
        except urllib2.URLError as e:
            self.log("[-] Gemini API 网络错误: {}".format(str(e)))
            self.log("[*] 使用默认模型列表")
            return self.get_default_models()
        except Exception as e:
            self.log("[-] Gemini获取模型失败: {}".format(str(e)))
            self.log("[*] 使用默认模型列表")
            return self.get_default_models()
    
    def parse_models_response(self, response_data):
        try:
            if 'models' in response_data:
                models = []
                all_models_count = len(response_data['models'])
                self.log("[+] Gemini API 返回了 {} 个模型（总数）".format(all_models_count))
                
                for model in response_data['models']:
                    model_name = model.get('name', '')
                    if model_name.startswith('models/'):
                        model_name = model_name[7:]
                    
                    # Get supported methods
                    supported_methods = model.get('supportedGenerationMethods', [])
                    
                    # Fixed: Check if model is deprecated and skip it
                    deprecation_info = model.get('deprecationInfo', {})
                    if deprecation_info:
                        self.log("[*] 跳过已弃用模型: {}".format(model_name))
                        continue
                    
                    # Only add models that support generateContent
                    if model_name and 'generateContent' in supported_methods:
                        models.append(model_name)
                        self.log("[+] 发现可用模型: {}".format(model_name))
                
                self.log("[+] 筛选后可用的 Gemini 模型数量: {}".format(len(models)))
                return models
            else:
                self.log("[-] 响应中没有 'models' 字段")
                return self.get_default_models()
        except Exception as e:
            self.log("[-] 解析Gemini模型列表出错: {}".format(str(e)))
            return self.get_default_models()
    
    def get_default_models(self):
        return ["gemini-pro", "gemini-pro-vision", "gemini-1.5-pro", "gemini-1.5-flash"]


class ClaudeProvider(APIProvider):
    """Anthropic Claude API provider"""
    
    def __init__(self, api_key, model="claude-3-sonnet-20240229", api_url="https://api.anthropic.com/v1/messages", timeout=60):
        super(ClaudeProvider, self).__init__(api_key, api_url, model, timeout)
        self.anthropic_version = "2023-06-01"
    
    def build_request_data(self, prompt, max_tokens):
        return {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens
        }
    
    def build_headers(self):
        return {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "Accept": "*/*",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    
    def parse_response(self, response_data):
        try:
            content = response_data["content"][0]["text"]
            usage = response_data.get("usage", {})
            
            return {
                "content": content,
                "usage": {
                    "prompt_tokens": usage.get("input_tokens", 0),
                    "completion_tokens": usage.get("output_tokens", 0),
                    "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                }
            }
        except (KeyError, IndexError) as e:
            raise Exception("Failed to parse Claude response: {}".format(str(e)))
    
    def get_models_url(self):
        return None
    
    def parse_models_response(self, response_data):
        return self.get_default_models()
    
    def get_default_models(self):
        return [
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1"
        ]


class ProviderFactory:
    """Factory for creating API provider instances"""
    
    PROVIDER_TYPES = {
        "OpenAI": OpenAIProvider,
        "Gemini": GeminiProvider,
        "Claude": ClaudeProvider,
        "DeepSeek": OpenAIProvider,
        "Ollama": OpenAIProvider,
        "Custom": OpenAIProvider
    }
    
    @staticmethod
    def create_provider(provider_type, api_key, api_url, model, timeout=60):
        """Create API provider instance"""
        provider_class = ProviderFactory.PROVIDER_TYPES.get(provider_type)
        
        if not provider_class:
            raise ValueError("Unsupported provider type: {}".format(provider_type))
        
        if provider_type == "Gemini":
            return GeminiProvider(api_key, model, timeout)
        elif provider_type == "Claude":
            return ClaudeProvider(api_key, model, api_url, timeout)
        else:
            return provider_class(api_key, api_url, model, timeout)
    
    @staticmethod
    def get_provider_types():
        """Get all supported provider types"""
        return list(ProviderFactory.PROVIDER_TYPES.keys())
    
    @staticmethod
    def get_default_config(provider_type):
        """Get default configuration for provider"""
        configs = {
            "OpenAI": {
                "api_url": "https://api.openai.com/v1/chat/completions",
                "model": "gpt-4o",
                "requires_url": True
            },
            "Gemini": {
                "api_url": "",
                "model": "gemini-pro",
                "requires_url": False
            },
            "Claude": {
                "api_url": "https://api.anthropic.com/v1/messages",
                "model": "claude-3-sonnet-20240229",
                "requires_url": True
            },
            "DeepSeek": {
                "api_url": "https://api.deepseek.com/v1/chat/completions",
                "model": "deepseek-chat",
                "requires_url": True
            },
            "Ollama": {
                "api_url": "http://localhost:11434/v1/chat/completions",
                "model": "llama2",
                "requires_url": True
            },
            "Custom": {
                "api_url": "https://api.example.com/v1/chat/completions",
                "model": "gpt-3.5-turbo",
                "requires_url": True
            }
        }
        return configs.get(provider_type, configs["Custom"])

# ============================================================================
# Burp Extension
# ============================================================================

class BurpExtender(IBurpExtender, IContextMenuFactory, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        
        # Default configuration
        self.provider_type = "OpenAI"
        self.api_key = "Please enter your API key"
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.model = "gpt-4o"
        self.max_tokens = 3072
        self.timeout_seconds = 60
        self.disable_ssl_verification = False
        self.max_request_length = 1000
        self.max_response_length = 2000
        
        # Proxy configuration
        self.enable_proxy = False
        self.proxy_type = "HTTP"
        self.proxy_host = "127.0.0.1"
        self.proxy_port = "10809"
        self.proxy_username = ""
        self.proxy_password = ""
        
        self.executor = Executors.newCachedThreadPool()
        
        self.tab = JTabbedPane()
        
        self.log_panel = JPanel(BorderLayout())
        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        log_scroll = JScrollPane(self.log_area)
        self.log_panel.add(log_scroll, BorderLayout.CENTER)
        
        config_panel = self.create_config_panel()
        results_panel = self.create_results_panel()
        
        self.tab.addTab("Configuration", config_panel)
        self.tab.addTab("Analysis Results", results_panel)
        self.tab.addTab("Logs", self.log_panel)
        
        callbacks.setExtensionName("Enhanced BurpGPT")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerScannerCheck(self)
        callbacks.addSuiteTab(self)
        
        self.debug = True
        
        default_prompt = """Answer in Chinese. Please analyze this HTTP request and response:

Request:
{REQUEST}

Response:
{RESPONSE}

Please identify any security issues and suggest fixes."""
        
        self.prompt_area.setText(default_prompt)
        
        System.setProperty("jsse.enableSNIExtension", "false")
        System.setProperty("https.protocols", "TLSv1.2")
        System.setProperty("javax.net.ssl.trustStore", "")
        System.setProperty("javax.net.ssl.trustStorePassword", "")
        
    def create_config_panel(self):
        config_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(5, 10, 5, 10)
        
        api_panel = JPanel(GridBagLayout())
        api_panel.setBorder(BorderFactory.createTitledBorder("API Settings"))
        
        # Provider Type Selection
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 1
        constraints.weightx = 0.2
        api_panel.add(JLabel("Provider Type:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.provider_combo = JComboBox(ProviderFactory.get_provider_types())
        self.provider_combo.setSelectedItem(self.provider_type)
        self.provider_combo.setToolTipText("Select API provider type")
        
        def on_provider_change(event):
            selected = str(self.provider_combo.getSelectedItem())
            config = ProviderFactory.get_default_config(selected)
            self.url_field.setText(config["api_url"])
            self.url_field.setEnabled(config["requires_url"])
            self.model_combo.removeAllItems()
            self.model_combo.addItem(config["model"])
            self.log("[*] Provider changed to: {}".format(selected))
        
        self.provider_combo.addActionListener(on_provider_change)
        api_panel.add(self.provider_combo, constraints)
        
        # API URL
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0.2
        api_panel.add(JLabel("API URL:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.url_field = JTextField(self.api_url, 40)
        self.url_field.setToolTipText("Enter the API endpoint URL")
        api_panel.add(self.url_field, constraints)
        
        # API Key
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0.2
        api_panel.add(JLabel("API Key:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.key_field = JTextField(self.api_key, 40)
        self.key_field.setToolTipText("Enter your API key")
        api_panel.add(self.key_field, constraints)
        
        # Model
        constraints.gridx = 0
        constraints.gridy = 3
        constraints.weightx = 0.2
        api_panel.add(JLabel("Model:"), constraints)
        
        self.model_combo = JComboBox()
        self.model_combo.setEditable(True)
        self.model_combo.setToolTipText("Select or enter the model name to use")
        self.model_combo.addItem(self.model)
        
        fetch_models_button = JButton("Fetch Models")
        fetch_models_button.setToolTipText("Fetch available models from API")
        
        model_panel = JPanel(BorderLayout())
        model_panel.add(self.model_combo, BorderLayout.CENTER)
        model_panel.add(fetch_models_button, BorderLayout.EAST)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        api_panel.add(model_panel, constraints)
        
        # SSL Options
        constraints.gridx = 0
        constraints.gridy = 4
        constraints.weightx = 0.2
        api_panel.add(JLabel("SSL Options:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.disable_ssl_check = JCheckBox("Disable SSL Certificate Validation", self.disable_ssl_verification)
        self.disable_ssl_check.setToolTipText("Enable this if you encounter SSL certificate issues")
        api_panel.add(self.disable_ssl_check, constraints)
        
        # Proxy panel
        from javax.swing import JPasswordField
        proxy_panel = JPanel(GridBagLayout())
        proxy_panel.setBorder(BorderFactory.createTitledBorder("Proxy Settings"))
        
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.weightx = 0.2
        proxy_panel.add(JLabel("Enable Proxy:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.enable_proxy_check = JCheckBox("Use proxy for API requests", self.enable_proxy)
        self.enable_proxy_check.setToolTipText("Enable if you need to use a proxy")
        proxy_panel.add(self.enable_proxy_check, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0.2
        proxy_panel.add(JLabel("Proxy Type:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.proxy_type_combo = JComboBox(["HTTP", "HTTPS", "SOCKS5"])
        self.proxy_type_combo.setSelectedItem(self.proxy_type)
        self.proxy_type_combo.setToolTipText("Select proxy type ")
        proxy_panel.add(self.proxy_type_combo, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0.2
        proxy_panel.add(JLabel("Proxy Host:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.proxy_host_field = JTextField(self.proxy_host, 20)
        self.proxy_host_field.setToolTipText("Proxy server address (e.g., 127.0.0.1)")
        proxy_panel.add(self.proxy_host_field, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 3
        constraints.weightx = 0.2
        proxy_panel.add(JLabel("Proxy Port:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.proxy_port_field = JTextField(self.proxy_port, 10)
        self.proxy_port_field.setToolTipText("Proxy port ")
        proxy_panel.add(self.proxy_port_field, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 4
        constraints.weightx = 0.2
        proxy_panel.add(JLabel("Username (optional):"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.proxy_username_field = JTextField(self.proxy_username, 20)
        self.proxy_username_field.setToolTipText("Leave empty if no authentication required")
        proxy_panel.add(self.proxy_username_field, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 5
        constraints.weightx = 0.2
        proxy_panel.add(JLabel("Password (optional):"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.proxy_password_field = JPasswordField(self.proxy_password, 20)
        self.proxy_password_field.setToolTipText("Leave empty if no authentication required")
        proxy_panel.add(self.proxy_password_field, constraints)
        
        # Limits panel
        limits_panel = JPanel(GridBagLayout())
        limits_panel.setBorder(BorderFactory.createTitledBorder("Limits & Timeouts"))
        
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.weightx = 0.2
        limits_panel.add(JLabel("Timeout (seconds):"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.timeout_field = JTextField(str(self.timeout_seconds), 10)
        self.timeout_field.setToolTipText("Maximum time to wait for API response")
        limits_panel.add(self.timeout_field, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 1
        constraints.weightx = 0.2
        limits_panel.add(JLabel("Max Request Length:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.req_length_field = JTextField(str(self.max_request_length), 10)
        self.req_length_field.setToolTipText("Maximum length of request content to analyze")
        limits_panel.add(self.req_length_field, constraints)
        
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.weightx = 0.2
        limits_panel.add(JLabel("Max Response Length:"), constraints)
        
        constraints.gridx = 1
        constraints.weightx = 0.8
        self.resp_length_field = JTextField(str(self.max_response_length), 10)
        self.resp_length_field.setToolTipText("Maximum length of response content to analyze")
        limits_panel.add(self.resp_length_field, constraints)
        
        # Prompt panel
        prompt_panel = JPanel(GridBagLayout())
        prompt_panel.setBorder(BorderFactory.createTitledBorder("Prompt Template"))
        
        constraints.gridx = 0
        constraints.gridy = 0
        constraints.gridwidth = 2
        constraints.weighty = 1.0
        self.prompt_area = JTextArea(5, 40)
        self.prompt_area.setLineWrap(True)
        self.prompt_area.setWrapStyleWord(True)
        self.prompt_area.setToolTipText("Template for analysis prompt")
        prompt_scroll = JScrollPane(self.prompt_area)
        prompt_panel.add(prompt_scroll, constraints)
        
        # Button panel
        button_panel = JPanel()
        button_panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 10, 0))
        
        def fetch_models(event):
            try:
                provider_type = str(self.provider_combo.getSelectedItem())
                api_key = self.key_field.getText()
                api_url = self.url_field.getText()
                model = str(self.model_combo.getSelectedItem()) if self.model_combo.getSelectedItem() else "gpt-4o"
                
                if not api_key:
                    JOptionPane.showMessageDialog(None, "Please enter API Key first!")
                    return
                
                self.log("[+] Fetching models from {} provider".format(provider_type))
                
                # Create progress dialog
                progress_dialog = JDialog()
                progress_dialog.setTitle("Fetching Models...")
                progress_dialog.setSize(300, 100)
                progress_dialog.setLocationRelativeTo(None)
                progress_dialog.setLayout(BorderLayout())
                
                progress_bar = JProgressBar()
                progress_bar.setIndeterminate(True)
                label = JLabel("Fetching available models...", SwingUtilities.CENTER)
                progress_dialog.add(label, BorderLayout.NORTH)
                progress_dialog.add(progress_bar, BorderLayout.CENTER)
                
                # Create async task for fetching models
                class FetchModelsTask(Runnable):
                    def __init__(self, outer):
                        self.outer = outer
                    
                    def run(self):
                        try:
                            SwingUtilities.invokeLater(lambda: progress_dialog.setVisible(True))
                            
                            provider = ProviderFactory.create_provider(
                                provider_type, api_key, api_url, model, self.outer.timeout_seconds
                            )
                            provider.set_log_callback(self.outer.log)
                            provider.disable_ssl = self.outer.disable_ssl_check.isSelected()
                            
                            # Configure proxy if enabled
                            if self.outer.enable_proxy_check.isSelected():
                                provider.set_proxy(
                                    str(self.outer.proxy_type_combo.getSelectedItem()),
                                    self.outer.proxy_host_field.getText(),
                                    self.outer.proxy_port_field.getText(),
                                    self.outer.proxy_username_field.getText(),
                                    String(self.outer.proxy_password_field.getPassword())
                                )
                            
                            models = provider.fetch_models()
                            
                            def update_models_ui():
                                try:
                                    progress_dialog.dispose()
                                    
                                    if models:
                                        self.outer.model_combo.removeAllItems()
                                        for model_name in models:
                                            self.outer.model_combo.addItem(model_name)
                                        self.outer.log("[+] Successfully fetched {} models".format(len(models)))
                                        JOptionPane.showMessageDialog(None, "Successfully fetched {} models!".format(len(models)))
                                    else:
                                        raise Exception("No models returned")
                                except Exception as e:
                                    error_msg = "Error updating models: {}".format(str(e))
                                    self.outer.log("[-] " + error_msg)
                                    JOptionPane.showMessageDialog(None, error_msg)
                            
                            SwingUtilities.invokeLater(update_models_ui)
                            
                        except Exception as e:
                            error_msg = "Error fetching models: {}".format(str(e))
                            self.outer.log("[-] " + error_msg)
                            SwingUtilities.invokeLater(lambda: progress_dialog.dispose())
                            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(None, error_msg))
                
                Thread(FetchModelsTask(self)).start()
                
            except Exception as e:
                error_msg = "Error initializing fetch: {}".format(str(e))
                self.log("[-] " + error_msg)
                JOptionPane.showMessageDialog(None, error_msg)
        
        fetch_models_button.addActionListener(fetch_models)
        
        def save_config(event):
            try:
                self.provider_type = str(self.provider_combo.getSelectedItem())
                self.api_url = self.url_field.getText()
                self.api_key = self.key_field.getText()
                self.model = str(self.model_combo.getSelectedItem())
                self.timeout_seconds = int(self.timeout_field.getText())
                self.max_request_length = int(self.req_length_field.getText())
                self.max_response_length = int(self.resp_length_field.getText())
                self.disable_ssl_verification = self.disable_ssl_check.isSelected()
                
                # Save proxy settings
                self.enable_proxy = self.enable_proxy_check.isSelected()
                self.proxy_type = str(self.proxy_type_combo.getSelectedItem())
                self.proxy_host = self.proxy_host_field.getText()
                self.proxy_port = self.proxy_port_field.getText()
                self.proxy_username = self.proxy_username_field.getText()
                self.proxy_password = String(self.proxy_password_field.getPassword())
                
                # Validate required fields
                if not self.api_key or not self.model:
                    JOptionPane.showMessageDialog(None, "API Key and Model cannot be empty!")
                    return
                
                # Warn if using Custom provider with example URL
                if self.provider_type == "Custom":
                    if not self.api_url or self.api_url.strip() == "":
                        JOptionPane.showMessageDialog(None, "Warning: API URL cannot be empty for Custom provider!")
                        return
                    
                    if "api.example.com" in self.api_url:
                        result = JOptionPane.showConfirmDialog(None, 
                            "You are using the example API URL.\n\n" +
                            "Please replace it with your actual API endpoint.\n\n" +
                            "Do you want to save anyway?",
                            "Example URL Detected",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE)
                        if result != JOptionPane.YES_OPTION:
                            return
                    
                    if self.model == "gpt-3.5-turbo":
                        result = JOptionPane.showConfirmDialog(None,
                            "You are using the default model name 'gpt-3.5-turbo'.\n\n" +
                            "Make sure this model exists in your custom API.\n\n" +
                            "Do you want to save anyway?",
                            "Default Model Name",
                            JOptionPane.YES_NO_OPTION,
                            JOptionPane.WARNING_MESSAGE)
                        if result != JOptionPane.YES_OPTION:
                            return
                    
                JOptionPane.showMessageDialog(None, "Configuration saved successfully!")
                
                self.log("[+] Configuration updated:")
                self.log("  - Provider: {}".format(self.provider_type))
                self.log("  - API URL: {}".format(self.api_url))
                self.log("  - Model: {}".format(self.model))
                self.log("  - SSL Verification: {}".format("Disabled" if self.disable_ssl_verification else "Enabled"))
                self.log("  - Proxy: {}".format("Enabled ({}://{}:{})".format(
                    self.proxy_type, self.proxy_host, self.proxy_port) if self.enable_proxy else "Disabled"))
                
            except Exception as e:
                JOptionPane.showMessageDialog(None, "Error saving configuration: " + str(e))
                self.log("[-] Error saving configuration: {}".format(str(e)))
        
        def reset_config(event):
            if JOptionPane.showConfirmDialog(None, 
                "Are you sure you want to reset all settings to default values?",
                "Confirm Reset",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
                self.provider_combo.setSelectedItem("OpenAI")
                self.url_field.setText("https://api.openai.com/v1/chat/completions")
                self.key_field.setText("Please enter your API key")
                self.model_combo.removeAllItems()
                self.model_combo.addItem("gpt-4o")
                self.timeout_field.setText("60")
                self.req_length_field.setText("1000")
                self.resp_length_field.setText("2000")
                self.disable_ssl_check.setSelected(False)
                self.enable_proxy_check.setSelected(False)
                self.proxy_type_combo.setSelectedItem("HTTP")
                self.proxy_host_field.setText("127.0.0.1")
                self.proxy_port_field.setText("10809")
                self.proxy_username_field.setText("")
                self.proxy_password_field.setText("")
                self.prompt_area.setText(self.get_default_prompt())
        
        save_button = JButton("Save Configuration")
        save_button.setToolTipText("Save current configuration")
        reset_button = JButton("Reset to Defaults")
        reset_button.setToolTipText("Reset all settings to default values")
        
        save_button.addActionListener(save_config)
        reset_button.addActionListener(reset_config)
        
        button_panel.add(save_button)
        button_panel.add(Box.createHorizontalStrut(10))
        button_panel.add(reset_button)
        
        # Assemble panels
        main_constraints = GridBagConstraints()
        main_constraints.fill = GridBagConstraints.HORIZONTAL
        main_constraints.insets = Insets(5, 5, 5, 5)
        main_constraints.gridx = 0
        main_constraints.gridy = 0
        main_constraints.weightx = 1.0
        config_panel.add(api_panel, main_constraints)
        
        main_constraints.gridy = 1
        config_panel.add(proxy_panel, main_constraints)
        
        main_constraints.gridy = 2
        config_panel.add(limits_panel, main_constraints)
        
        main_constraints.gridy = 3
        main_constraints.weighty = 1.0
        main_constraints.fill = GridBagConstraints.BOTH
        config_panel.add(prompt_panel, main_constraints)
        
        main_constraints.gridy = 4
        main_constraints.weighty = 0.0
        main_constraints.fill = GridBagConstraints.HORIZONTAL
        config_panel.add(button_panel, main_constraints)
        
        return config_panel
        
    def get_default_prompt(self):
        return """Please analyze this HTTP request and response:

URL: {URL}
Method: {METHOD}

Request:
{REQUEST}

Response:
{RESPONSE}

Please identify any security issues and suggest fixes."""
        
    def create_results_panel(self):
        results_panel = JPanel(BorderLayout())
        
        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        split_pane.setDividerLocation(200)
        
        toolbar = JPanel()
        clear_button = JButton("Clear Results")
        search_field = JTextField(20)
        search_button = JButton("Search")
        export_button = JButton("Export Results")
        
        self.list_model = DefaultListModel()
        self.analysis_list = JList(self.list_model)
        analysis_scroll = JScrollPane(self.analysis_list)
        
        self.results_area = JTextArea()
        self.results_area.setEditable(False)
        results_scroll = JScrollPane(self.results_area)
        
        class SelectionListener(ListSelectionListener):
            def __init__(self, outer):
                self.outer = outer
            
            def valueChanged(self, event):
                if not event.getValueIsAdjusting():
                    index = self.outer.analysis_list.getSelectedIndex()
                    if index >= 0:
                        result = self.outer.analysis_results[index]
                        self.outer.display_result_details(result)
        
        self.analysis_list.addListSelectionListener(SelectionListener(self))
        self.analysis_results = []
        
        def clear_results(event):
            self.list_model.clear()
            self.analysis_results = []
            self.results_area.setText("")
        clear_button.addActionListener(clear_results)
        
        def search_results(event):
            search_text = search_field.getText().lower()
            if search_text:
                for i in range(self.list_model.size()):
                    if search_text in self.list_model.getElementAt(i).lower():
                        self.analysis_list.setSelectedIndex(i)
                        self.analysis_list.ensureIndexIsVisible(i)
                        break
        search_button.addActionListener(search_results)
        
        def export_results(event):
            try:
                if self.analysis_results:
                    timestamp = java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(java.util.Date())
                    filename = "gpt_analysis_{}.txt".format(timestamp)
                    from java.io import FileWriter, BufferedWriter
                    writer = BufferedWriter(FileWriter(filename))
                    try:
                        writer.write("Enhanced BurpGPT Analysis Report\n")
                        writer.write("=" * 50 + "\n")
                        writer.write("Export Time: {}\n".format(timestamp))
                        writer.write("Total Results: {}\n".format(len(self.analysis_results)))
                        writer.write("=" * 50 + "\n\n")
                        for index, result in enumerate(self.analysis_results, 1):
                            writer.write("Analysis #{}\n".format(index))
                            writer.write("-" * 30 + "\n")
                            writer.write("Time: {}\n".format(result.time))
                            writer.write("URL: {}\n".format(result.url))
                            writer.write("\nAnalysis Result:\n")
                            writer.write("-" * 30 + "\n")
                            writer.write(result.response)
                            writer.write("\n" + "=" * 50 + "\n\n")
                        JOptionPane.showMessageDialog(None, "Results exported to {}".format(filename))
                        self.log("[+] Exported {} analysis results to {}".format(len(self.analysis_results), filename))
                    finally:
                        writer.close()
            except Exception as e:
                error_msg = "Export failed: {}".format(str(e))
                JOptionPane.showMessageDialog(None, error_msg)
                self.log("[-] " + error_msg)
        export_button.addActionListener(export_results)
        
        toolbar.add(clear_button)
        toolbar.add(search_field)
        toolbar.add(search_button)
        toolbar.add(export_button)
        
        split_pane.setTopComponent(analysis_scroll)
        split_pane.setBottomComponent(results_scroll)
        
        results_panel.add(toolbar, BorderLayout.NORTH)
        results_panel.add(split_pane, BorderLayout.CENTER)
        
        return results_panel
        
    def send_to_gpt(self, invocation):
        try:
            current_time = System.currentTimeMillis()
            if hasattr(self, '_last_trigger_time') and (current_time - self._last_trigger_time < 1000):
                self.log("[*] Ignoring duplicate trigger")
                return
            self._last_trigger_time = current_time
            
            self.log("[+] Send to GPT method called")
            http_msgs = invocation.getSelectedMessages()
            self.log("[+] Selected messages: {}".format(len(http_msgs)))
            
            if http_msgs and len(http_msgs) == 1:
                msg = http_msgs[0]
                url = msg.getUrl().toString()
                self.log("[+] Processing URL: {}".format(url))
                
                progress_dialog = JDialog()
                progress_dialog.setTitle("Analyzing...")
                progress_dialog.setSize(300, 100)
                progress_dialog.setLocationRelativeTo(None)
                progress_dialog.setLayout(BorderLayout())
                
                progress_bar = JProgressBar()
                progress_bar.setIndeterminate(True)
                label = JLabel("GPT is analyzing the request/response...", SwingUtilities.CENTER)
                progress_dialog.add(label, BorderLayout.NORTH)
                progress_dialog.add(progress_bar, BorderLayout.CENTER)
                
                class AsyncTask(Runnable):
                    def __init__(self, outer):
                        self.outer = outer
                    
                    def run(self):
                        response_time = 0
                        try:
                            self.outer.log("[+] AsyncTask started")
                            SwingUtilities.invokeLater(lambda: progress_dialog.setVisible(True))
                            
                            self.outer.log("[+] Creating GPT request with truncation limits")
                            gpt_request = GPTRequest(
                                self.outer._helpers, 
                                msg, 
                                self.outer.model, 
                                self.outer.max_tokens,
                                self.outer.max_request_length,
                                self.outer.max_response_length,
                                self.outer.log
                            )
                            gpt_request.set_prompt(self.outer.prompt_area.getText())
                            
                            self.outer.log("[+] Sending request to API")
                            
                            # Measure response time
                            start_time = System.currentTimeMillis()
                            gpt_response = self.outer.call_gpt_api(gpt_request)
                            end_time = System.currentTimeMillis()
                            response_time = end_time - start_time
                            
                            self.outer.log("[+] Received response from API (took {:.2f}s)".format(response_time / 1000.0))
                            
                            def update_ui():
                                try:
                                    self.outer.log("[+] Updating UI")
                                    progress_dialog.dispose()
                                    
                                    if isinstance(gpt_response, dict):
                                        content = gpt_response.get("content", "")
                                        usage = gpt_response.get("usage", {})
                                        if content:
                                            self.outer.update_results(url, content, usage, response_time)
                                        else:
                                            self.outer.update_results(url, "No valid analysis result received.", {}, response_time)
                                    else:
                                        error_msg = "Error: {}".format(str(gpt_response))
                                        self.outer.update_results(url, error_msg, {}, response_time)
                                    
                                    self.outer.log("[+] UI updated successfully")
                                except Exception as e:
                                    self.outer.log("[-] Error in update_ui: {}".format(str(e)))
                            
                            SwingUtilities.invokeLater(update_ui)
                        except Exception as e:
                            self.outer.log("[-] Error in AsyncTask: {}".format(str(e)))
                            SwingUtilities.invokeLater(lambda: progress_dialog.dispose())
                            SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(None, "Error: {}".format(str(e))))
                
                Thread(AsyncTask(self)).start()
            else:
                self.log("[-] No message selected or multiple messages selected")
        except Exception as e:
            self.log("[-] Error in send_to_gpt: {}".format(str(e)))
            
    def call_gpt_api(self, gpt_request):
        """Call GPT API using the provider adapter"""
        try:
            self.log("[+] Using provider: {}".format(self.provider_type))
            
            provider = ProviderFactory.create_provider(
                self.provider_type,
                self.api_key,
                self.api_url,
                self.model,
                self.timeout_seconds
            )
            provider.set_log_callback(self.log)
            provider.disable_ssl = self.disable_ssl_verification
            
            # Configure proxy if enabled
            if self.enable_proxy:
                provider.set_proxy(
                    self.proxy_type,
                    self.proxy_host,
                    self.proxy_port,
                    self.proxy_username,
                    self.proxy_password
                )
            
            result = provider.send_request(gpt_request.prompt, self.max_tokens)
            return result
            
        except Exception as e:
            self.log("[-] Error calling API: {}".format(str(e)))
            raise Exception("Error calling API: {}".format(str(e)))
    
    def truncate_content(self, content, max_length):
        if not content:
            return ""
        try:
            content_str = self._helpers.bytesToString(content)
        except:
            content_str = str(content)
        
        if len(content_str) <= max_length:
            return content_str
        
        headers_end = content_str.find("\r\n\r\n")
        if headers_end == -1:
            return content_str[:max_length] + "\n... (content truncated)"
        
        headers = content_str[:headers_end]
        body = content_str[headers_end+4:]
        remaining_length = max_length - len(headers) - 50
        
        if remaining_length <= 0:
            return content_str[:max_length] + "\n... (content truncated)"
        
        truncated_body = body[:remaining_length]
        return "{}\r\n\r\n{}\n... (content truncated, total length: {})".format(headers, truncated_body, len(content_str))
    
    def getTabCaption(self):
        return "GPT Analysis"
        
    def getUiComponent(self):
        return self.tab

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Send to GPT")
        menu_item.addActionListener(lambda x: self.send_to_gpt(invocation))
        menu_list.add(menu_item)
        return menu_list

    def log(self, message):
        self.stdout.println(message)
        if hasattr(self, 'log_area'):
            SwingUtilities.invokeLater(lambda: self.log_area.append(message + "\n"))
            SwingUtilities.invokeLater(lambda: self.log_area.setCaretPosition(self.log_area.getDocument().getLength()))

    def update_results(self, url, content, usage, response_time=0):
        timestamp = java.text.SimpleDateFormat("HH:mm:ss").format(java.util.Date())
        result = AnalysisResult(timestamp, url, content, usage, response_time)
        self.analysis_results.append(result)
        
        # Include token count in list display
        tokens_str = " [{}T]".format(result.total_tokens) if result.total_tokens > 0 else ""
        self.list_model.addElement("[{}] {}{}".format(timestamp, url, tokens_str))
        
        last_index = self.list_model.size() - 1
        self.analysis_list.setSelectedIndex(last_index)
        self.analysis_list.ensureIndexIsVisible(last_index)
        
        # Log token usage
        if result.total_tokens > 0:
            self.log("[+] Token usage: {} total ({} prompt + {} completion)".format(
                result.total_tokens, result.prompt_tokens, result.completion_tokens))

    def display_result_details(self, result):
        self.results_area.setText("")
        self.results_area.append("="*50 + "\n")
        self.results_area.append("Analysis Time: {}\n".format(result.time))
        self.results_area.append("Target URL: {}\n".format(result.url))
        
        # Display token usage statistics
        if result.total_tokens > 0:
            self.results_area.append("\n[Token Usage]\n")
            self.results_area.append("  Prompt Tokens: {}\n".format(result.prompt_tokens))
            self.results_area.append("  Completion Tokens: {}\n".format(result.completion_tokens))
            self.results_area.append("  Total Tokens: {}\n".format(result.total_tokens))
        
        # Display performance metrics
        if result.response_time > 0:
            self.results_area.append("  Response Time: {:.2f}s\n".format(result.response_time / 1000.0))
        
        self.results_area.append("-"*50 + "\n")
        self.results_area.append(result.response + "\n")
        self.results_area.append("="*50 + "\n")
        self.results_area.setCaretPosition(0)


class GPTRequest:
    def __init__(self, helpers, http_message, model, max_tokens, max_request_length=1000, max_response_length=2000, log_callback=None):
        try:
            request_info = helpers.analyzeRequest(http_message)
            self.url = str(http_message.getUrl())
            self.method = str(request_info.getMethod())
            
            # Get raw request and response
            request_bytes = http_message.getRequest()
            raw_request = helpers.bytesToString(request_bytes)
            response_bytes = http_message.getResponse()
            raw_response = helpers.bytesToString(response_bytes) if response_bytes else ""
            
            # Apply smart truncation to request and response
            self.request = ContentTruncator.smart_truncate(raw_request, max_request_length, "request")
            self.response = ContentTruncator.smart_truncate(raw_response, max_response_length, "response")
            
            # Log truncation info if callback provided
            if log_callback:
                if len(raw_request) > max_request_length:
                    log_callback("[*] Request truncated: {} chars -> {} chars".format(len(raw_request), max_request_length))
                if len(raw_response) > max_response_length:
                    log_callback("[*] Response truncated: {} chars -> {} chars".format(len(raw_response), max_response_length))
            
            self.model = model
            self.max_tokens = max_tokens
            self.prompt = None
            self.log_callback = log_callback
        except Exception as e:
            raise Exception("Error initializing GPTRequest: " + str(e))

    def set_prompt(self, prompt_template):
        """Build prompt from template with variable substitution"""
        try:
            prompt = prompt_template
            prompt = prompt.replace("{URL}", self.url)
            prompt = prompt.replace("{METHOD}", self.method)
            prompt = prompt.replace("{REQUEST}", self.request)
            prompt = prompt.replace("{RESPONSE}", self.response)
            
            # Store the final prompt
            self.prompt = prompt
            
            # Log final prompt size
            if self.log_callback:
                self.log_callback("[*] Final prompt size: {} characters".format(len(prompt)))
            
            return prompt
        except Exception as e:
            raise Exception("Error setting prompt: " + str(e))


class AnalysisResult:
    """Enhanced analysis result with token usage tracking"""
    
    def __init__(self, time, url, response, usage=None, response_time=0):
        self.time = time
        self.url = url
        self.response = response
        self.severity = "Information"
        self.notes = ""
        
        # Token usage statistics
        if usage is None:
            usage = {}
        self.prompt_tokens = usage.get("prompt_tokens", 0)
        self.completion_tokens = usage.get("completion_tokens", 0)
        self.total_tokens = usage.get("total_tokens", 0)
        
        # Performance metrics
        self.response_time = response_time  # in milliseconds
        
    def get_tokens_display(self):
        """Get formatted token usage string"""
        return "Tokens: {} prompt + {} completion = {} total".format(
            self.prompt_tokens,
            self.completion_tokens,
            self.total_tokens
        )
    
    def get_performance_display(self):
        """Get formatted performance string"""
        if self.response_time > 0:
            return "Response time: {:.2f}s".format(self.response_time / 1000.0)
        return ""
        
    def __str__(self):
        return "[{}] {}".format(self.time, self.url)
