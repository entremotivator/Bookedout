import streamlit as st
import streamlit.components.v1 as components
import base64
import requests
import json
import time
from datetime import datetime
import re
import io
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
import ebooklib
from ebooklib import epub
import tempfile
import os
import traceback
from typing import Dict, List, Tuple, Any, Optional

# Import validation utilities
try:
    from validation_utils import (
        WebhookValidator, 
        ValidationError, 
        PayloadTooLargeError, 
        RateLimitError,
        create_error_response,
        log_webhook_error,
        rate_limiter
    )
except ImportError:
    # Fallback if validation_utils is not available
    class WebhookValidator:
        @staticmethod
        def validate_webhook_payload(payload):
            return True, []
        @staticmethod
        def sanitize_payload(payload):
            return payload
    
    class ValidationError(Exception):
        pass
    
    class PayloadTooLargeError(Exception):
        pass
    
    class RateLimitError(Exception):
        pass
    
    def create_error_response(error_type, message, details=None):
        return {'error': True, 'message': message}
    
    def log_webhook_error(webhook_type, error, payload_size=0):
        print(f"Error in {webhook_type}: {error}")
    
    class RateLimiter:
        def check_rate_limit(self, user_id, webhook_type):
            return True, "OK"
    
    rate_limiter = RateLimiter()

# Configuration - 10 Different Webhook Endpoints
WEBHOOK_URLS = {
    'audio': 'https://agentonline-u29564.vm.elestio.app/webhook-test/audio-files',
    'books': 'https://agentonline-u29564.vm.elestio.app/webhook-test/books-content',
    'lectures': 'https://agentonline-u29564.vm.elestio.app/webhook-test/lectures-education',
    'podcasts': 'https://agentonline-u29564.vm.elestio.app/webhook-test/podcasts-episodes',
    'notes': 'https://agentonline-u29564.vm.elestio.app/webhook-test/notes-thoughts',
    'documents': 'https://agentonline-u29564.vm.elestio.app/webhook-test/documents-files',
    'videos': 'https://agentonline-u29564.vm.elestio.app/webhook-test/videos-content',
    'images': 'https://agentonline-u29564.vm.elestio.app/webhook-test/images-photos',
    'research': 'https://agentonline-u29564.vm.elestio.app/webhook-test/research-data',
    'meetings': 'https://agentonline-u29564.vm.elestio.app/webhook-test/meetings-records'
}

# Content type configurations
CONTENT_TYPES = {
    'audio': {
        'name': '🎵 Audio Files',
        'description': 'Voice recordings, music files, audio memos',
        'icon': '🎵',
        'color': '#FF6B6B',
        'fields': ['title', 'description', 'duration', 'quality', 'format']
    },
    'books': {
        'name': '📚 Books',
        'description': 'Book content, chapters, reading materials',
        'icon': '📚',
        'color': '#4ECDC4',
        'fields': ['title', 'author', 'genre', 'chapter', 'page_count']
    },
    'lectures': {
        'name': '🎓 Lectures',
        'description': 'Educational content, presentations, courses',
        'icon': '🎓',
        'color': '#45B7D1',
        'fields': ['title', 'instructor', 'subject', 'duration', 'slides']
    },
    'podcasts': {
        'name': '🎙️ Podcasts',
        'description': 'Podcast episodes, audio shows, interviews',
        'icon': '🎙️',
        'color': '#96CEB4',
        'fields': ['title', 'host', 'episode', 'duration', 'show_name']
    },
    'notes': {
        'name': '📝 Notes',
        'description': 'Personal notes, thoughts, reminders',
        'icon': '📝',
        'color': '#FFEAA7',
        'fields': ['title', 'tags', 'priority', 'category', 'reminder']
    },
    'documents': {
        'name': '📄 Documents',
        'description': 'Formal documents, reports, papers',
        'icon': '📄',
        'color': '#DDA0DD',
        'fields': ['title', 'type', 'version', 'author', 'department']
    },
    'videos': {
        'name': '🎬 Videos',
        'description': 'Video content, recordings, tutorials',
        'icon': '🎬',
        'color': '#74B9FF',
        'fields': ['title', 'duration', 'resolution', 'format', 'category']
    },
    'images': {
        'name': '🖼️ Images',
        'description': 'Photos, graphics, visual content',
        'icon': '🖼️',
        'color': '#FD79A8',
        'fields': ['title', 'dimensions', 'format', 'location', 'tags']
    },
    'research': {
        'name': '🔬 Research',
        'description': 'Research data, studies, findings',
        'icon': '🔬',
        'color': '#00B894',
        'fields': ['title', 'methodology', 'subject', 'author', 'institution']
    },
    'meetings': {
        'name': '🤝 Meetings',
        'description': 'Meeting recordings, minutes, action items',
        'icon': '🤝',
        'color': '#E17055',
        'fields': ['title', 'participants', 'duration', 'agenda', 'outcomes']
    }
}

# Page configuration
st.set_page_config(
    page_title="🎙️ Book Buddy - Multi-Webhook Edition", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0,0,0,0.1);
    }
    
    .webhook-selector {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 1.5rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        color: white;
    }
    
    .content-type-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 16px rgba(0,0,0,0.1);
        margin-bottom: 1rem;
        border-left: 4px solid var(--accent-color);
        transition: transform 0.2s ease;
    }
    
    .content-type-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(0,0,0,0.15);
    }
    
    .status-success {
        background: linear-gradient(135deg, #4CAF50, #45a049);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .status-error {
        background: linear-gradient(135deg, #f44336, #d32f2f);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .status-info {
        background: linear-gradient(135deg, #2196F3, #1976D2);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        text-align: center;
        border: 1px solid #dee2e6;
    }
    
    .webhook-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin: 1rem 0;
    }
    
    .stat-item {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    
    .webhook-history {
        max-height: 300px;
        overflow-y: auto;
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .history-item {
        background: white;
        padding: 0.5rem;
        margin: 0.5rem 0;
        border-radius: 4px;
        border-left: 3px solid #007bff;
        font-size: 0.9rem;
    }
    
    .success-item {
        border-left-color: #28a745;
    }
    
    .error-item {
        border-left-color: #dc3545;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
def initialize_session_state():
    """Initialize all session state variables with enhanced webhook support"""
    defaults = {
        'selected_webhook_type': 'audio',
        'webhook_urls': WEBHOOK_URLS.copy(),
        'recording_title': '',
        'recording_description': '',
        'user_name': 'Multi-Webhook User',
        'content_metadata': {},
        'content': '',
        'webhook_responses': [],
        'last_recording': None,
        'audio_quality': 'High',
        'auto_send': True,
        'show_advanced': False,
        'webhook_stats': {webhook_type: {'sent': 0, 'success': 0, 'errors': 0} for webhook_type in WEBHOOK_URLS.keys()},
        'batch_mode': False,
        'selected_webhooks': []
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

# Utility functions
def validate_webhook_url(url):
    """Validate webhook URL format"""
    try:
        import urllib.parse
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def format_file_size(size_bytes):
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"

def create_payload_for_webhook_type(webhook_type, content_data, metadata):
    """Create type-specific payload for different webhook types"""
    base_payload = {
        'webhook_type': webhook_type,
        'timestamp': datetime.now().isoformat(),
        'user_info': {
            'name': st.session_state.user_name,
            'session_id': st.session_state.get('session_id', 'default-session')
        },
        'content': {
            'primary_data': content_data,
            'metadata': metadata
        },
        'processing_options': {
            'quality': st.session_state.audio_quality,
            'auto_process': st.session_state.auto_send
        }
    }
    
    # Add type-specific fields
    type_specific = {}
    
    if webhook_type == 'audio':
        type_specific.update({
            'format': metadata.get('format', 'webm'),
            'duration': metadata.get('duration', 0),
            'sample_rate': metadata.get('sample_rate', 44100)
        })
    elif webhook_type == 'books':
        type_specific.update({
            'author': metadata.get('author', ''),
            'genre': metadata.get('genre', ''),
            'chapter': metadata.get('chapter', ''),
            'page_count': metadata.get('page_count', 0)
        })
    elif webhook_type == 'lectures':
        type_specific.update({
            'instructor': metadata.get('instructor', ''),
            'subject': metadata.get('subject', ''),
            'course_code': metadata.get('course_code', ''),
            'slides_count': metadata.get('slides_count', 0)
        })
    elif webhook_type == 'podcasts':
        type_specific.update({
            'host': metadata.get('host', ''),
            'episode_number': metadata.get('episode_number', ''),
            'show_name': metadata.get('show_name', ''),
            'guest': metadata.get('guest', '')
        })
    elif webhook_type == 'notes':
        type_specific.update({
            'tags': metadata.get('tags', []),
            'priority': metadata.get('priority', 'medium'),
            'category': metadata.get('category', 'general'),
            'reminder_date': metadata.get('reminder_date', '')
        })
    elif webhook_type == 'documents':
        type_specific.update({
            'document_type': metadata.get('document_type', ''),
            'version': metadata.get('version', '1.0'),
            'department': metadata.get('department', ''),
            'classification': metadata.get('classification', 'public')
        })
    elif webhook_type == 'videos':
        type_specific.update({
            'resolution': metadata.get('resolution', '1080p'),
            'format': metadata.get('format', 'mp4'),
            'fps': metadata.get('fps', 30),
            'codec': metadata.get('codec', 'h264')
        })
    elif webhook_type == 'images':
        type_specific.update({
            'dimensions': metadata.get('dimensions', ''),
            'format': metadata.get('format', 'jpg'),
            'location': metadata.get('location', ''),
            'camera_info': metadata.get('camera_info', '')
        })
    elif webhook_type == 'research':
        type_specific.update({
            'methodology': metadata.get('methodology', ''),
            'subject_area': metadata.get('subject_area', ''),
            'institution': metadata.get('institution', ''),
            'funding_source': metadata.get('funding_source', '')
        })
    elif webhook_type == 'meetings':
        type_specific.update({
            'participants': metadata.get('participants', []),
            'agenda_items': metadata.get('agenda_items', []),
            'action_items': metadata.get('action_items', []),
            'meeting_type': metadata.get('meeting_type', 'general')
        })
    
    base_payload['content']['type_specific_fields'] = type_specific
    return base_payload

def send_to_webhook(payload, webhook_type=None):
    """Enhanced webhook sending with comprehensive error handling and validation"""
    webhook_type = webhook_type or st.session_state.selected_webhook_type
    url = st.session_state.webhook_urls[webhook_type]
    
    try:
        # Rate limiting check
        user_id = st.session_state.get('user_name', 'anonymous')
        rate_ok, rate_msg = rate_limiter.check_rate_limit(user_id, webhook_type)
        if not rate_ok:
            raise RateLimitError(rate_msg)
        
        # Payload validation
        is_valid, validation_errors = WebhookValidator.validate_webhook_payload(payload)
        if not is_valid:
            raise ValidationError(validation_errors)
        
        # Sanitize payload
        payload = WebhookValidator.sanitize_payload(payload)
        
        # Check payload size
        payload_json = json.dumps(payload)
        payload_size = len(payload_json.encode('utf-8'))
        
        # 10MB limit for payload
        if payload_size > 10 * 1024 * 1024:
            raise PayloadTooLargeError(f"Payload too large: {format_file_size(payload_size)} (max 10MB)")
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': f'Book-Buddy-Multi-Webhook/2.0.0-{webhook_type}',
            'X-Webhook-Type': webhook_type,
            'X-Content-Type': webhook_type,
            'X-Payload-Size': str(payload_size),
            'X-User-ID': user_id
        }
        
        # Update stats
        st.session_state.webhook_stats[webhook_type]['sent'] += 1
        
        # Send request with retry logic
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    url, 
                    json=payload, 
                    headers=headers, 
                    timeout=30,
                    verify=True  # SSL verification
                )
                break
            except requests.exceptions.Timeout:
                if attempt == max_retries - 1:
                    raise
                time.sleep(retry_delay * (attempt + 1))
            except requests.exceptions.ConnectionError:
                if attempt == max_retries - 1:
                    raise
                time.sleep(retry_delay * (attempt + 1))
        
        # Store response in session state
        response_data = {
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'status_code': response.status_code,
            'success': response.status_code == 200,
            'payload_size': payload_size,
            'response_text': response.text[:500] if response.text else None,
            'url': url,
            'attempt_count': attempt + 1,
            'validation_passed': True
        }
        
        st.session_state.webhook_responses.insert(0, response_data)
        # Keep only last 20 responses
        st.session_state.webhook_responses = st.session_state.webhook_responses[:20]
        
        if response.status_code == 200:
            st.session_state.webhook_stats[webhook_type]['success'] += 1
            return True, f"✅ Successfully sent to {CONTENT_TYPES[webhook_type]['name']} webhook!", response_data
        elif response.status_code == 429:
            # Rate limited by server
            st.session_state.webhook_stats[webhook_type]['errors'] += 1
            return False, f"⚠️ Rate limited by server. Please try again later.", response_data
        elif response.status_code >= 500:
            # Server error
            st.session_state.webhook_stats[webhook_type]['errors'] += 1
            return False, f"🔧 Server error ({response.status_code}). Please try again later.", response_data
        elif response.status_code >= 400:
            # Client error
            st.session_state.webhook_stats[webhook_type]['errors'] += 1
            return False, f"❌ Request error ({response.status_code}): {response.text[:100]}", response_data
        else:
            st.session_state.webhook_stats[webhook_type]['errors'] += 1
            return False, f"⚠️ Unexpected response ({response.status_code})", response_data
            
    except ValidationError as e:
        error_data = {
            'error': 'Validation failed',
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'validation_errors': e.errors if hasattr(e, 'errors') else [str(e)],
            'validation_passed': False
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e)
        return False, f"❌ Validation failed: {str(e)[:100]}...", error_data
        
    except PayloadTooLargeError as e:
        error_data = {
            'error': 'Payload too large',
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'payload_size': payload_size if 'payload_size' in locals() else 0
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e, payload_size if 'payload_size' in locals() else 0)
        return False, f"📦 {str(e)}", error_data
        
    except RateLimitError as e:
        error_data = {
            'error': 'Rate limit exceeded',
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e)
        return False, f"🚦 {str(e)}", error_data
        
    except requests.exceptions.Timeout:
        error_data = {
            'error': 'Request timeout', 
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'timeout_duration': 30
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, requests.exceptions.Timeout("Request timeout"))
        return False, "⏱️ Request timed out after 30 seconds. Please check your connection.", error_data
        
    except requests.exceptions.ConnectionError as e:
        error_data = {
            'error': 'Connection error', 
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'connection_error': str(e)
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e)
        return False, "🔌 Could not connect to webhook. Please check the URL and your internet connection.", error_data
        
    except requests.exceptions.SSLError as e:
        error_data = {
            'error': 'SSL certificate error', 
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'ssl_error': str(e)
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e)
        return False, "🔒 SSL certificate error. Please check the webhook URL.", error_data
        
    except json.JSONEncodeError as e:
        error_data = {
            'error': 'JSON encoding error', 
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'json_error': str(e)
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e)
        return False, "📄 Failed to encode payload as JSON. Please check your data.", error_data
        
    except Exception as e:
        error_data = {
            'error': 'Unexpected error', 
            'timestamp': datetime.now().isoformat(),
            'webhook_type': webhook_type,
            'url': url,
            'exception_type': type(e).__name__,
            'exception_message': str(e),
            'traceback': traceback.format_exc()
        }
        st.session_state.webhook_responses.insert(0, error_data)
        st.session_state.webhook_stats[webhook_type]['errors'] += 1
        log_webhook_error(webhook_type, e)
        return False, f"💥 Unexpected error: {str(e)[:100]}...", error_data

def send_to_multiple_webhooks(payload, webhook_types):
    """Send payload to multiple webhooks simultaneously with error handling"""
    results = {}
    
    if not webhook_types:
        return {'error': 'No webhook types specified'}
    
    # Validate payload once before sending to multiple webhooks
    try:
        is_valid, validation_errors = WebhookValidator.validate_webhook_payload(payload)
        if not is_valid:
            error_msg = f"Validation failed: {'; '.join(validation_errors[:3])}..."
            return {webhook_type: {'success': False, 'message': error_msg, 'data': {'validation_errors': validation_errors}} for webhook_type in webhook_types}
    except Exception as e:
        error_msg = f"Validation error: {str(e)}"
        return {webhook_type: {'success': False, 'message': error_msg, 'data': {'error': str(e)}} for webhook_type in webhook_types}
    
    # Send to each webhook
    for webhook_type in webhook_types:
        try:
            if webhook_type not in CONTENT_TYPES:
                results[webhook_type] = {
                    'success': False, 
                    'message': f"Invalid webhook type: {webhook_type}", 
                    'data': {'error': 'Invalid webhook type'}
                }
                continue
            
            success, message, data = send_to_webhook(payload, webhook_type)
            results[webhook_type] = {'success': success, 'message': message, 'data': data}
            
        except Exception as e:
            results[webhook_type] = {
                'success': False, 
                'message': f"Error sending to {webhook_type}: {str(e)[:100]}...", 
                'data': {'error': str(e), 'exception_type': type(e).__name__}
            }
            log_webhook_error(webhook_type, e)
    
    return results

def create_enhanced_voice_recorder():
    """Create enhanced voice recorder with webhook type selection"""
    webhook_type = st.session_state.selected_webhook_type
    webhook_config = CONTENT_TYPES[webhook_type]
    webhook_url = st.session_state.webhook_urls[webhook_type]
    title = st.session_state.recording_title
    description = st.session_state.recording_description
    user_name = st.session_state.user_name
    auto_send = st.session_state.auto_send
    
    recorder_html = f"""
    <div id="voice-recorder-enhanced" style="
        background: linear-gradient(135deg, {webhook_config['color']}, {webhook_config['color']}CC);
        padding: 30px;
        border-radius: 20px;
        margin: 20px 0;
        box-shadow: 0 12px 40px rgba(0,0,0,0.15);
        color: white;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    ">
        <div style="text-align: center; margin-bottom: 25px;">
            <h2 style="margin: 0 0 10px 0; font-size: 28px; font-weight: 700;">
                {webhook_config['icon']} Enhanced Voice Recorder
            </h2>
            <p style="margin: 0; opacity: 0.9; font-size: 16px;">
                Recording for {webhook_config['name']} - {webhook_config['description']}
            </p>
        </div>
        
        <!-- Webhook Status -->
        <div style="
            background: rgba(255,255,255,0.15);
            padding: 15px;
            border-radius: 12px;
            margin-bottom: 25px;
            backdrop-filter: blur(10px);
        ">
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap;">
                <div>
                    <strong>{webhook_config['icon']} Target:</strong> 
                    <span style="font-family: monospace; font-size: 12px; opacity: 0.8;">{webhook_url[-30:]}...</span>
                </div>
                <div style="margin-top: 5px;">
                    <span style="background: rgba(76, 175, 80, 0.8); padding: 4px 12px; border-radius: 15px; font-size: 12px;">
                        ✅ Auto-send: {'ON' if auto_send else 'OFF'}
                    </span>
                </div>
            </div>
        </div>
        
        <!-- Recording Controls -->
        <div style="text-align: center; margin-bottom: 25px;">
            <button id="recordBtn" style="
                background: linear-gradient(45deg, #ff6b6b, #ff8e8e);
                color: white;
                border: none;
                padding: 20px 40px;
                font-size: 18px;
                border-radius: 50px;
                cursor: pointer;
                margin: 0 10px;
                transition: all 0.3s ease;
                box-shadow: 0 8px 25px rgba(255, 107, 107, 0.4);
                font-weight: bold;
                min-width: 180px;
            ">🎙️ Start Recording</button>
            
            <button id="stopBtn" disabled style="
                background: linear-gradient(45deg, #666, #888);
                color: white;
                border: none;
                padding: 20px 40px;
                font-size: 18px;
                border-radius: 50px;
                cursor: not-allowed;
                margin: 0 10px;
                transition: all 0.3s ease;
                font-weight: bold;
                min-width: 180px;
            ">⏹️ Stop Recording</button>
        </div>
        
        <!-- Status Display -->
        <div id="statusDisplay" style="
            text-align: center;
            font-size: 18px;
            font-weight: 600;
            margin: 20px 0;
            min-height: 30px;
        ">{webhook_config['icon']} Ready to record for {webhook_config['name']}</div>
        
        <!-- Waveform Visualization -->
        <div id="waveformContainer" style="
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 20px;
            margin: 25px 0;
            display: none;
            position: relative;
            height: 100px;
            overflow: hidden;
        ">
            <div id="waveform" style="
                display: flex;
                align-items: end;
                justify-content: center;
                height: 100%;
                gap: 2px;
            "></div>
        </div>
        
        <!-- Recording Stats -->
        <div id="recordingStats" style="
            display: none;
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 12px;
            margin: 20px 0;
        ">
            <div style="display: flex; justify-content: space-around; text-align: center;">
                <div>
                    <div style="font-size: 24px; font-weight: bold;" id="duration">00:00</div>
                    <div style="font-size: 12px; opacity: 0.8;">Duration</div>
                </div>
                <div>
                    <div style="font-size: 24px; font-weight: bold;" id="fileSize">0 KB</div>
                    <div style="font-size: 12px; opacity: 0.8;">Size</div>
                </div>
                <div>
                    <div style="font-size: 24px; font-weight: bold;" id="quality">High</div>
                    <div style="font-size: 12px; opacity: 0.8;">Quality</div>
                </div>
            </div>
        </div>
        
        <!-- Audio Playback -->
        <div id="playbackContainer" style="display: none; margin: 25px 0;">
            <div style="margin-bottom: 15px; text-align: center;">
                <strong>🎵 Recording Playback</strong>
            </div>
            <audio id="audioPlayback" controls style="
                width: 100%;
                border-radius: 10px;
                background: rgba(255,255,255,0.1);
            "></audio>
        </div>
        
        <!-- Webhook Status -->
        <div id="webhookStatus" style="
            display: none;
            padding: 15px;
            border-radius: 12px;
            margin: 20px 0;
            text-align: center;
            font-weight: 600;
        "></div>
        
        <!-- Progress Bar -->
        <div id="progressContainer" style="display: none; margin: 20px 0;">
            <div style="background: rgba(255,255,255,0.2); border-radius: 10px; overflow: hidden;">
                <div id="progressBar" style="
                    background: linear-gradient(45deg, #4CAF50, #45a049);
                    height: 8px;
                    width: 0%;
                    transition: width 0.3s ease;
                "></div>
            </div>
            <div id="progressText" style="text-align: center; margin-top: 10px; font-size: 14px;"></div>
        </div>
        
        <textarea id="base64output" style="display: none;"></textarea>
    </div>

    <script>
    let mediaRecorder;
    let audioChunks = [];
    let isRecording = false;
    let recordingTimer;
    let seconds = 0;
    let audioContext;
    let analyser;
    let dataArray;
    let animationId;
    let stream;

    const recordBtn = document.getElementById("recordBtn");
    const stopBtn = document.getElementById("stopBtn");
    const statusDisplay = document.getElementById("statusDisplay");
    const playback = document.getElementById("audioPlayback");
    const base64output = document.getElementById("base64output");
    const waveformContainer = document.getElementById("waveformContainer");
    const waveform = document.getElementById("waveform");
    const recordingStats = document.getElementById("recordingStats");
    const playbackContainer = document.getElementById("playbackContainer");
    const webhookStatus = document.getElementById("webhookStatus");
    const progressContainer = document.getElementById("progressContainer");
    const progressBar = document.getElementById("progressBar");
    const progressText = document.getElementById("progressText");
    
    const durationSpan = document.getElementById("duration");
    const fileSizeSpan = document.getElementById("fileSize");
    const qualitySpan = document.getElementById("quality");

    function updateProgress(percent, text) {{
        progressContainer.style.display = 'block';
        progressBar.style.width = percent + '%';
        progressText.textContent = text;
        
        if (percent >= 100) {{
            setTimeout(() => {{
                progressContainer.style.display = 'none';
            }}, 2000);
        }}
    }}

    function showWebhookStatus(message, isSuccess = true) {{
        webhookStatus.style.display = 'block';
        webhookStatus.textContent = message;
        webhookStatus.style.background = isSuccess 
            ? 'rgba(76, 175, 80, 0.8)' 
            : 'rgba(244, 67, 54, 0.8)';
        
        setTimeout(() => {{
            webhookStatus.style.display = 'none';
        }}, 5000);
    }}

    function updateButtonStyles() {{
        if (isRecording) {{
            recordBtn.style.background = "linear-gradient(45deg, #666, #888)";
            recordBtn.style.cursor = "not-allowed";
            recordBtn.style.transform = "scale(0.95)";
            recordBtn.style.boxShadow = "0 4px 15px rgba(0,0,0,0.2)";
            
            stopBtn.style.background = "linear-gradient(45deg, #ff4757, #ff6b6b)";
            stopBtn.style.cursor = "pointer";
            stopBtn.style.boxShadow = "0 8px 25px rgba(255, 71, 87, 0.5)";
            stopBtn.style.transform = "scale(1.05)";
        }} else {{
            recordBtn.style.background = "linear-gradient(45deg, #ff6b6b, #ff8e8e)";
            recordBtn.style.cursor = "pointer";
            recordBtn.style.transform = "scale(1)";
            recordBtn.style.boxShadow = "0 8px 25px rgba(255, 107, 107, 0.4)";
            
            stopBtn.style.background = "linear-gradient(45deg, #666, #888)";
            stopBtn.style.cursor = "not-allowed";
            stopBtn.style.transform = "scale(0.95)";
            stopBtn.style.boxShadow = "0 4px 15px rgba(0,0,0,0.2)";
        }}
    }}

    function startTimer() {{
        seconds = 0;
        recordingStats.style.display = 'block';
        recordingTimer = setInterval(() => {{
            seconds++;
            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            durationSpan.textContent = `${{mins.toString().padStart(2, '0')}}:${{secs.toString().padStart(2, '0')}}`;
            statusDisplay.innerHTML = `🔴 Recording for {webhook_config['name']}... ${{mins}}:${{secs.toString().padStart(2, '0')}}`;
        }}, 1000);
    }}

    function stopTimer() {{
        if (recordingTimer) {{
            clearInterval(recordingTimer);
            recordingTimer = null;
        }}
    }}

    function createWaveform() {{
        waveform.innerHTML = '';
        for (let i = 0; i < 50; i++) {{
            const bar = document.createElement('div');
            bar.style.width = '3px';
            bar.style.backgroundColor = 'rgba(255,255,255,0.7)';
            bar.style.borderRadius = '2px';
            bar.style.height = '10px';
            bar.style.transition = 'height 0.1s ease';
            waveform.appendChild(bar);
        }}
    }}

    function animateWaveform() {{
        if (!analyser || !isRecording) return;
        
        analyser.getByteFrequencyData(dataArray);
        const bars = waveform.children;
        
        for (let i = 0; i < bars.length; i++) {{
            const value = dataArray[i * 2] || 0;
            const height = Math.max(10, (value / 255) * 80);
            bars[i].style.height = height + 'px';
        }}
        
        if (isRecording) {{
            animationId = requestAnimationFrame(animateWaveform);
        }}
    }}

    async function startRecording() {{
        try {{
            updateProgress(10, 'Requesting microphone access...');
            
            stream = await navigator.mediaDevices.getUserMedia({{ 
                audio: {{
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true,
                    sampleRate: 44100
                }}
            }});
            
            updateProgress(30, 'Setting up audio processing...');
            
            // Setup audio context for visualization
            audioContext = new (window.AudioContext || window.webkitAudioContext)();
            analyser = audioContext.createAnalyser();
            const source = audioContext.createMediaStreamSource(stream);
            source.connect(analyser);
            
            analyser.fftSize = 256;
            const bufferLength = analyser.frequencyBinCount;
            dataArray = new Uint8Array(bufferLength);
            
            updateProgress(50, 'Initializing recorder...');
            
            mediaRecorder = new MediaRecorder(stream, {{
                mimeType: 'audio/webm;codecs=opus'
            }});
            
            audioChunks = [];
            
            mediaRecorder.ondataavailable = (event) => {{
                if (event.data.size > 0) {{
                    audioChunks.push(event.data);
                    const currentSize = audioChunks.reduce((total, chunk) => total + chunk.size, 0);
                    fileSizeSpan.textContent = formatFileSize(currentSize);
                }}
            }};
            
            mediaRecorder.onstop = async () => {{
                updateProgress(70, 'Processing recording...');
                
                const audioBlob = new Blob(audioChunks, {{ type: 'audio/webm' }});
                const audioUrl = URL.createObjectURL(audioBlob);
                playback.src = audioUrl;
                playbackContainer.style.display = 'block';
                
                updateProgress(85, 'Converting to base64...');
                
                const reader = new FileReader();
                reader.onload = () => {{
                    const base64 = reader.result.split(',')[1];
                    base64output.value = base64;
                    
                    updateProgress(100, 'Recording complete!');
                    
                    if ({str(auto_send).lower()}) {{
                        showWebhookStatus('Auto-sending to {webhook_config["name"]} webhook...', true);
                        setTimeout(() => {{
                            const event = new Event('input', {{ bubbles: true }});
                            base64output.dispatchEvent(event);
                        }}, 1000);
                    }} else {{
                        showWebhookStatus('Recording ready. Use "Send to Webhook" button to send.', true);
                    }}
                }};
                reader.readAsDataURL(audioBlob);
                
                // Cleanup
                stream.getTracks().forEach(track => track.stop());
                if (audioContext) {{
                    audioContext.close();
                }}
            }};
            
            updateProgress(80, 'Starting recording...');
            
            mediaRecorder.start(1000); // Collect data every second
            isRecording = true;
            
            recordBtn.disabled = true;
            stopBtn.disabled = false;
            updateButtonStyles();
            
            waveformContainer.style.display = 'block';
            createWaveform();
            animateWaveform();
            startTimer();
            
            updateProgress(100, 'Recording in progress...');
            
        }} catch (error) {{
            console.error('Error starting recording:', error);
            showWebhookStatus('Error: ' + error.message, false);
            updateProgress(0, '');
        }}
    }}

    function stopRecording() {{
        if (mediaRecorder && isRecording) {{
            mediaRecorder.stop();
            isRecording = false;
            
            recordBtn.disabled = false;
            stopBtn.disabled = true;
            updateButtonStyles();
            
            stopTimer();
            
            if (animationId) {{
                cancelAnimationFrame(animationId);
            }}
            
            statusDisplay.innerHTML = '{webhook_config["icon"]} Recording completed for {webhook_config["name"]}';
        }}
    }}

    function formatFileSize(bytes) {{
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }}

    // Event listeners
    recordBtn.addEventListener("click", startRecording);
    stopBtn.addEventListener("click", stopRecording);
    
    // Initialize
    updateButtonStyles();
    </script>
    """
    
    return recorder_html

def render_webhook_selector():
    """Render the webhook type selector"""
    st.markdown('<div class="webhook-selector">', unsafe_allow_html=True)
    st.markdown("### 🎯 Select Content Type & Webhook")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Create options for selectbox
        options = []
        for key, config in CONTENT_TYPES.items():
            options.append(f"{config['icon']} {config['name']} - {config['description']}")
        
        selected_option = st.selectbox(
            "Choose the type of content you're recording:",
            options,
            index=list(CONTENT_TYPES.keys()).index(st.session_state.selected_webhook_type)
        )
        
        # Extract the key from the selected option
        selected_key = list(CONTENT_TYPES.keys())[options.index(selected_option)]
        st.session_state.selected_webhook_type = selected_key
    
    with col2:
        st.markdown("#### Batch Mode")
        st.session_state.batch_mode = st.checkbox("Send to multiple webhooks", value=st.session_state.batch_mode)
        
        if st.session_state.batch_mode:
            st.session_state.selected_webhooks = st.multiselect(
                "Select webhooks:",
                list(CONTENT_TYPES.keys()),
                default=st.session_state.selected_webhooks,
                format_func=lambda x: f"{CONTENT_TYPES[x]['icon']} {CONTENT_TYPES[x]['name']}"
            )
    
    st.markdown('</div>', unsafe_allow_html=True)

def render_content_metadata_form():
    """Render dynamic form based on selected webhook type"""
    webhook_type = st.session_state.selected_webhook_type
    config = CONTENT_TYPES[webhook_type]
    
    st.markdown(f"### {config['icon']} {config['name']} Metadata")
    
    # Initialize metadata if not exists
    if webhook_type not in st.session_state.content_metadata:
        st.session_state.content_metadata[webhook_type] = {}
    
    metadata = st.session_state.content_metadata[webhook_type]
    
    col1, col2 = st.columns(2)
    
    with col1:
        metadata['title'] = st.text_input(
            "Title", 
            value=metadata.get('title', ''),
            key=f"title_{webhook_type}"
        )
        
        if 'author' in config['fields']:
            metadata['author'] = st.text_input(
                "Author", 
                value=metadata.get('author', ''),
                key=f"author_{webhook_type}"
            )
        
        if 'genre' in config['fields']:
            metadata['genre'] = st.selectbox(
                "Genre",
                ['Fiction', 'Non-Fiction', 'Science', 'Technology', 'History', 'Biography', 'Other'],
                index=['Fiction', 'Non-Fiction', 'Science', 'Technology', 'History', 'Biography', 'Other'].index(metadata.get('genre', 'Fiction')),
                key=f"genre_{webhook_type}"
            )
        
        if 'priority' in config['fields']:
            metadata['priority'] = st.selectbox(
                "Priority",
                ['low', 'medium', 'high', 'urgent'],
                index=['low', 'medium', 'high', 'urgent'].index(metadata.get('priority', 'medium')),
                key=f"priority_{webhook_type}"
            )
    
    with col2:
        metadata['description'] = st.text_area(
            "Description", 
            value=metadata.get('description', ''),
            height=100,
            key=f"description_{webhook_type}"
        )
        
        if 'tags' in config['fields']:
            tags_input = st.text_input(
                "Tags (comma-separated)", 
                value=', '.join(metadata.get('tags', [])),
                key=f"tags_{webhook_type}"
            )
            metadata['tags'] = [tag.strip() for tag in tags_input.split(',') if tag.strip()]
        
        if 'category' in config['fields']:
            metadata['category'] = st.selectbox(
                "Category",
                ['general', 'work', 'personal', 'project', 'research'],
                index=['general', 'work', 'personal', 'project', 'research'].index(metadata.get('category', 'general')),
                key=f"category_{webhook_type}"
            )
    
    # Store updated metadata
    st.session_state.content_metadata[webhook_type] = metadata

def render_webhook_stats():
    """Render webhook statistics"""
    st.markdown("### 📊 Webhook Statistics")
    
    stats = st.session_state.webhook_stats
    
    # Create metrics grid
    cols = st.columns(5)
    
    total_sent = sum(stat['sent'] for stat in stats.values())
    total_success = sum(stat['success'] for stat in stats.values())
    total_errors = sum(stat['errors'] for stat in stats.values())
    success_rate = (total_success / total_sent * 100) if total_sent > 0 else 0
    
    with cols[0]:
        st.metric("Total Sent", total_sent)
    with cols[1]:
        st.metric("Successful", total_success)
    with cols[2]:
        st.metric("Errors", total_errors)
    with cols[3]:
        st.metric("Success Rate", f"{success_rate:.1f}%")
    with cols[4]:
        st.metric("Active Webhooks", len([k for k, v in stats.items() if v['sent'] > 0]))
    
    # Individual webhook stats
    st.markdown("#### Individual Webhook Performance")
    
    for webhook_type, stat in stats.items():
        if stat['sent'] > 0:
            config = CONTENT_TYPES[webhook_type]
            success_rate = (stat['success'] / stat['sent'] * 100) if stat['sent'] > 0 else 0
            
            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            with col1:
                st.write(f"{config['icon']} {config['name']}")
            with col2:
                st.write(f"Sent: {stat['sent']}")
            with col3:
                st.write(f"Success: {stat['success']}")
            with col4:
                st.write(f"Rate: {success_rate:.1f}%")

def render_webhook_history():
    """Render webhook response history with enhanced error display"""
    st.markdown("### 📋 Recent Webhook Activity")
    
    if not st.session_state.webhook_responses:
        st.info("No webhook activity yet. Start recording to see activity here.")
        return
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_type = st.selectbox(
            "Filter by type:",
            ['All'] + list(CONTENT_TYPES.keys()),
            format_func=lambda x: f"{CONTENT_TYPES[x]['icon']} {CONTENT_TYPES[x]['name']}" if x != 'All' else 'All Types'
        )
    
    with col2:
        filter_status = st.selectbox(
            "Filter by status:",
            ['All', 'Success', 'Error', 'Validation Failed']
        )
    
    with col3:
        show_details = st.checkbox("Show detailed errors", value=False)
    
    # Filter responses
    filtered_responses = st.session_state.webhook_responses
    
    if filter_type != 'All':
        filtered_responses = [r for r in filtered_responses if r.get('webhook_type') == filter_type]
    
    if filter_status == 'Success':
        filtered_responses = [r for r in filtered_responses if r.get('success', False)]
    elif filter_status == 'Error':
        filtered_responses = [r for r in filtered_responses if not r.get('success', True) and r.get('validation_passed', True)]
    elif filter_status == 'Validation Failed':
        filtered_responses = [r for r in filtered_responses if not r.get('validation_passed', True)]
    
    # Display responses
    for i, response in enumerate(filtered_responses[:15]):  # Show last 15
        webhook_type = response.get('webhook_type', 'unknown')
        config = CONTENT_TYPES.get(webhook_type, {'icon': '❓', 'name': 'Unknown'})
        
        try:
            timestamp = datetime.fromisoformat(response['timestamp']).strftime("%H:%M:%S")
        except:
            timestamp = "Unknown"
        
        # Determine status and styling
        if response.get('success', False):
            status_color = "#28a745"
            status_text = "✅ Success"
            status_icon = "✅"
        elif not response.get('validation_passed', True):
            status_color = "#fd7e14"
            status_text = "⚠️ Validation Failed"
            status_icon = "⚠️"
        else:
            status_color = "#dc3545"
            status_text = "❌ Error"
            status_icon = "❌"
        
        # Main response card
        with st.container():
            st.markdown(f"""
            <div style="
                background: white;
                padding: 15px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 4px solid {status_color};
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            ">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div>
                        <strong>{config['icon']} {config['name']}</strong> - {status_text}
                    </div>
                    <div style="font-size: 0.9em; color: #666;">
                        {timestamp}
                    </div>
                </div>
                <div style="font-size: 0.8em; color: #666;">
                    Size: {format_file_size(response.get('payload_size', 0))} | 
                    Status: {response.get('status_code', 'N/A')} |
                    Attempts: {response.get('attempt_count', 1)}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Show detailed error information if requested
            if show_details and not response.get('success', False):
                with st.expander(f"🔍 Error Details - {config['name']}", expanded=False):
                    error_info = {}
                    
                    # Collect error information
                    if 'validation_errors' in response:
                        error_info['Validation Errors'] = response['validation_errors']
                    if 'error' in response:
                        error_info['Error Type'] = response['error']
                    if 'exception_type' in response:
                        error_info['Exception Type'] = response['exception_type']
                    if 'exception_message' in response:
                        error_info['Exception Message'] = response['exception_message']
                    if 'response_text' in response and response['response_text']:
                        error_info['Server Response'] = response['response_text']
                    if 'connection_error' in response:
                        error_info['Connection Error'] = response['connection_error']
                    if 'ssl_error' in response:
                        error_info['SSL Error'] = response['ssl_error']
                    if 'json_error' in response:
                        error_info['JSON Error'] = response['json_error']
                    if 'url' in response:
                        error_info['Target URL'] = response['url']
                    
                    # Display error information
                    for key, value in error_info.items():
                        if isinstance(value, list):
                            st.write(f"**{key}:**")
                            for item in value:
                                st.write(f"  • {item}")
                        else:
                            st.write(f"**{key}:** {value}")
                    
                    # Show traceback if available (for debugging)
                    if 'traceback' in response and st.checkbox(f"Show technical details", key=f"traceback_{i}"):
                        st.code(response['traceback'], language='python')
    
    # Summary statistics
    if filtered_responses:
        st.markdown("---")
        col1, col2, col3, col4 = st.columns(4)
        
        total_responses = len(filtered_responses)
        successful = len([r for r in filtered_responses if r.get('success', False)])
        validation_failed = len([r for r in filtered_responses if not r.get('validation_passed', True)])
        errors = total_responses - successful
        
        with col1:
            st.metric("Total", total_responses)
        with col2:
            st.metric("Successful", successful)
        with col3:
            st.metric("Validation Failed", validation_failed)
        with col4:
            st.metric("Other Errors", errors - validation_failed)

def render_webhook_configuration():
    """Render webhook URL configuration"""
    st.markdown("### ⚙️ Webhook Configuration")
    
    with st.expander("Configure Webhook URLs", expanded=False):
        st.warning("⚠️ Advanced users only. Changing these URLs will affect where your data is sent.")
        
        for webhook_type, url in st.session_state.webhook_urls.items():
            config = CONTENT_TYPES[webhook_type]
            new_url = st.text_input(
                f"{config['icon']} {config['name']}",
                value=url,
                key=f"webhook_url_{webhook_type}"
            )
            
            if new_url != url:
                if validate_webhook_url(new_url):
                    st.session_state.webhook_urls[webhook_type] = new_url
                    st.success(f"Updated {config['name']} webhook URL")
                else:
                    st.error(f"Invalid URL format for {config['name']}")

# Main application
def main():
    initialize_session_state()
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🎙️ Book Buddy - Multi-Webhook Edition</h1>
        <p>Professional content recording with 10 specialized webhook endpoints</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## 🎛️ Control Panel")
        
        # User settings
        st.session_state.user_name = st.text_input(
            "User Name", 
            value=st.session_state.user_name
        )
        
        st.session_state.audio_quality = st.selectbox(
            "Audio Quality",
            ['High', 'Medium', 'Low'],
            index=['High', 'Medium', 'Low'].index(st.session_state.audio_quality)
        )
        
        st.session_state.auto_send = st.checkbox(
            "Auto-send to webhook", 
            value=st.session_state.auto_send
        )
        
        st.session_state.show_advanced = st.checkbox(
            "Show advanced options", 
            value=st.session_state.show_advanced
        )
        
        st.markdown("---")
        
        # Quick stats
        st.markdown("### 📈 Quick Stats")
        total_sent = sum(stat['sent'] for stat in st.session_state.webhook_stats.values())
        total_success = sum(stat['success'] for stat in st.session_state.webhook_stats.values())
        
        st.metric("Total Recordings", total_sent)
        st.metric("Successful Sends", total_success)
        
        if total_sent > 0:
            success_rate = (total_success / total_sent) * 100
            st.metric("Success Rate", f"{success_rate:.1f}%")
    
    # Main content
    render_webhook_selector()
    
    # Content metadata form
    render_content_metadata_form()
    
    # Voice recorder
    st.markdown("### 🎙️ Voice Recorder")
    recorder_html = create_enhanced_voice_recorder()
    components.html(recorder_html, height=600)
    
    # Handle audio data
    audio_data = st.text_area("", key="audio_base64", label_visibility="hidden")
    
    if audio_data and audio_data != st.session_state.get('last_audio_data', ''):
        st.session_state.last_audio_data = audio_data
        
        # Create payload
        webhook_type = st.session_state.selected_webhook_type
        metadata = st.session_state.content_metadata.get(webhook_type, {})
        
        payload = create_payload_for_webhook_type(webhook_type, audio_data, metadata)
        
        if st.session_state.batch_mode and st.session_state.selected_webhooks:
            # Send to multiple webhooks
            results = send_to_multiple_webhooks(payload, st.session_state.selected_webhooks)
            
            success_count = sum(1 for r in results.values() if r['success'])
            total_count = len(results)
            
            if success_count == total_count:
                st.success(f"✅ Successfully sent to all {total_count} webhooks!")
            elif success_count > 0:
                st.warning(f"⚠️ Sent to {success_count}/{total_count} webhooks successfully")
            else:
                st.error(f"❌ Failed to send to all {total_count} webhooks")
        else:
            # Send to single webhook
            success, message, data = send_to_webhook(payload, webhook_type)
            
            if success:
                st.success(f"✅ {message}")
            else:
                st.error(f"❌ {message}")
    
    # Manual send button
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col2:
        if st.button("🚀 Send to Webhook", type="primary", use_container_width=True):
            if audio_data:
                webhook_type = st.session_state.selected_webhook_type
                metadata = st.session_state.content_metadata.get(webhook_type, {})
                payload = create_payload_for_webhook_type(webhook_type, audio_data, metadata)
                
                if st.session_state.batch_mode and st.session_state.selected_webhooks:
                    results = send_to_multiple_webhooks(payload, st.session_state.selected_webhooks)
                    
                    success_count = sum(1 for r in results.values() if r['success'])
                    total_count = len(results)
                    
                    if success_count == total_count:
                        st.success(f"✅ Successfully sent to all {total_count} webhooks!")
                    else:
                        st.warning(f"⚠️ Sent to {success_count}/{total_count} webhooks")
                else:
                    success, message, data = send_to_webhook(payload, webhook_type)
                    
                    if success:
                        st.success(f"✅ {message}")
                    else:
                        st.error(f"❌ {message}")
            else:
                st.warning("⚠️ No audio data to send. Please record something first.")
    
    # Statistics and history
    if st.session_state.show_advanced:
        st.markdown("---")
        
        tab1, tab2, tab3 = st.tabs(["📊 Statistics", "📋 History", "⚙️ Configuration"])
        
        with tab1:
            render_webhook_stats()
        
        with tab2:
            render_webhook_history()
        
        with tab3:
            render_webhook_configuration()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666; padding: 20px;">
        <p>🎙️ Book Buddy Multi-Webhook Edition v2.0 | 
        Supporting 10 specialized content types | 
        Built with ❤️ for content creators</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

