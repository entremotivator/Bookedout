"""
Comprehensive validation utilities for webhook payloads
Supports all 10 content types with specific validation rules
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import base64
import mimetypes

class WebhookValidator:
    """Comprehensive webhook payload validator"""
    
    # Content type specific validation rules
    VALIDATION_RULES = {
        'audio': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['description', 'duration', 'format', 'sample_rate'],
            'max_title_length': 200,
            'max_description_length': 1000,
            'allowed_formats': ['webm', 'mp3', 'wav', 'ogg', 'm4a'],
            'max_duration': 7200,  # 2 hours in seconds
            'min_duration': 1
        },
        'books': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['author', 'genre', 'chapter', 'page_count', 'isbn'],
            'max_title_length': 300,
            'max_author_length': 200,
            'allowed_genres': ['Fiction', 'Non-Fiction', 'Science', 'Technology', 'History', 'Biography', 'Mystery', 'Romance', 'Fantasy', 'Other'],
            'max_page_count': 10000,
            'min_page_count': 1
        },
        'lectures': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['instructor', 'subject', 'course_code', 'slides_count', 'institution'],
            'max_title_length': 250,
            'max_instructor_length': 150,
            'max_subject_length': 200,
            'max_slides_count': 1000,
            'min_slides_count': 1
        },
        'podcasts': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['host', 'episode_number', 'show_name', 'guest', 'season'],
            'max_title_length': 250,
            'max_host_length': 150,
            'max_show_name_length': 200,
            'max_guest_length': 300,
            'max_episode_number': 10000
        },
        'notes': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['tags', 'priority', 'category', 'reminder_date'],
            'max_title_length': 200,
            'max_tags_count': 20,
            'max_tag_length': 50,
            'allowed_priorities': ['low', 'medium', 'high', 'urgent'],
            'allowed_categories': ['general', 'work', 'personal', 'project', 'research', 'meeting', 'idea']
        },
        'documents': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['document_type', 'version', 'department', 'classification', 'author'],
            'max_title_length': 300,
            'allowed_document_types': ['report', 'proposal', 'manual', 'specification', 'contract', 'memo', 'other'],
            'allowed_classifications': ['public', 'internal', 'confidential', 'restricted'],
            'version_pattern': r'^\d+\.\d+(\.\d+)?$'
        },
        'videos': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['resolution', 'format', 'fps', 'codec', 'duration'],
            'max_title_length': 250,
            'allowed_resolutions': ['480p', '720p', '1080p', '1440p', '2160p', '4K', '8K'],
            'allowed_formats': ['mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv'],
            'allowed_codecs': ['h264', 'h265', 'vp8', 'vp9', 'av1'],
            'max_fps': 120,
            'min_fps': 1
        },
        'images': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['dimensions', 'format', 'location', 'camera_info', 'tags'],
            'max_title_length': 200,
            'allowed_formats': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp'],
            'max_location_length': 200,
            'dimension_pattern': r'^\d+x\d+$'
        },
        'research': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['methodology', 'subject_area', 'institution', 'funding_source', 'keywords'],
            'max_title_length': 400,
            'max_methodology_length': 500,
            'max_subject_area_length': 200,
            'max_institution_length': 200,
            'max_keywords_count': 15
        },
        'meetings': {
            'required_fields': ['title', 'primary_data'],
            'optional_fields': ['participants', 'agenda_items', 'action_items', 'meeting_type', 'location'],
            'max_title_length': 250,
            'max_participants_count': 100,
            'max_agenda_items_count': 50,
            'max_action_items_count': 50,
            'allowed_meeting_types': ['general', 'standup', 'review', 'planning', 'retrospective', 'training', 'interview']
        }
    }
    
    @staticmethod
    def validate_base64_audio(data: str) -> Tuple[bool, str]:
        """Validate base64 encoded audio data"""
        try:
            # Check if it's valid base64
            decoded = base64.b64decode(data)
            
            # Check minimum size (should be at least 1KB for valid audio)
            if len(decoded) < 1024:
                return False, "Audio data too small (minimum 1KB required)"
            
            # Check maximum size (50MB limit)
            if len(decoded) > 50 * 1024 * 1024:
                return False, "Audio data too large (maximum 50MB allowed)"
            
            return True, "Valid audio data"
            
        except Exception as e:
            return False, f"Invalid base64 audio data: {str(e)}"
    
    @staticmethod
    def validate_text_content(content: str, max_length: int = 100000) -> Tuple[bool, str]:
        """Validate text content"""
        if not content or not content.strip():
            return False, "Content cannot be empty"
        
        if len(content) > max_length:
            return False, f"Content too long (maximum {max_length} characters)"
        
        # Check for potentially malicious content
        suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*='
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, "Content contains potentially malicious code"
        
        return True, "Valid text content"
    
    @staticmethod
    def validate_email(email: str) -> Tuple[bool, str]:
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):
            return True, "Valid email"
        return False, "Invalid email format"
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str]:
        """Validate URL format"""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        if re.match(pattern, url):
            return True, "Valid URL"
        return False, "Invalid URL format"
    
    @staticmethod
    def validate_datetime(dt_string: str) -> Tuple[bool, str]:
        """Validate datetime string"""
        try:
            datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
            return True, "Valid datetime"
        except ValueError:
            return False, "Invalid datetime format (use ISO format)"
    
    @classmethod
    def validate_webhook_payload(cls, payload: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Comprehensive webhook payload validation
        Returns (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required top-level fields
        required_top_level = ['webhook_type', 'timestamp', 'user_info', 'content']
        for field in required_top_level:
            if field not in payload:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return False, errors
        
        # Validate webhook type
        webhook_type = payload['webhook_type']
        if webhook_type not in cls.VALIDATION_RULES:
            errors.append(f"Invalid webhook_type: {webhook_type}")
            return False, errors
        
        rules = cls.VALIDATION_RULES[webhook_type]
        
        # Validate timestamp
        is_valid, msg = cls.validate_datetime(payload['timestamp'])
        if not is_valid:
            errors.append(f"Invalid timestamp: {msg}")
        
        # Validate user_info
        user_info = payload.get('user_info', {})
        if not isinstance(user_info, dict):
            errors.append("user_info must be a dictionary")
        else:
            if 'name' not in user_info or not user_info['name'].strip():
                errors.append("user_info.name is required and cannot be empty")
        
        # Validate content
        content = payload.get('content', {})
        if not isinstance(content, dict):
            errors.append("content must be a dictionary")
            return False, errors
        
        # Check required content fields
        for field in rules['required_fields']:
            if field not in content:
                errors.append(f"Missing required content field: {field}")
        
        # Validate primary_data based on webhook type
        primary_data = content.get('primary_data', '')
        if webhook_type in ['audio', 'videos']:
            # Assume base64 encoded media
            is_valid, msg = cls.validate_base64_audio(primary_data)
            if not is_valid:
                errors.append(f"Invalid primary_data: {msg}")
        else:
            # Text content
            max_length = 100000  # Default max length
            if webhook_type == 'books':
                max_length = 1000000  # Books can be longer
            elif webhook_type == 'research':
                max_length = 500000  # Research can be longer
            
            is_valid, msg = cls.validate_text_content(primary_data, max_length)
            if not is_valid:
                errors.append(f"Invalid primary_data: {msg}")
        
        # Validate metadata
        metadata = content.get('metadata', {})
        if not isinstance(metadata, dict):
            errors.append("content.metadata must be a dictionary")
        else:
            # Validate title
            title = metadata.get('title', '')
            if title and len(title) > rules.get('max_title_length', 200):
                errors.append(f"Title too long (max {rules.get('max_title_length', 200)} characters)")
            
            # Type-specific validations
            errors.extend(cls._validate_type_specific_metadata(webhook_type, metadata, rules))
        
        # Validate type_specific_fields
        type_specific = content.get('type_specific_fields', {})
        if not isinstance(type_specific, dict):
            errors.append("content.type_specific_fields must be a dictionary")
        else:
            errors.extend(cls._validate_type_specific_fields(webhook_type, type_specific, rules))
        
        return len(errors) == 0, errors
    
    @classmethod
    def _validate_type_specific_metadata(cls, webhook_type: str, metadata: Dict[str, Any], rules: Dict[str, Any]) -> List[str]:
        """Validate type-specific metadata fields"""
        errors = []
        
        if webhook_type == 'books':
            genre = metadata.get('genre')
            if genre and genre not in rules.get('allowed_genres', []):
                errors.append(f"Invalid genre: {genre}")
            
            page_count = metadata.get('page_count')
            if page_count is not None:
                try:
                    page_count = int(page_count)
                    if page_count < rules.get('min_page_count', 1) or page_count > rules.get('max_page_count', 10000):
                        errors.append(f"Invalid page_count: must be between {rules.get('min_page_count', 1)} and {rules.get('max_page_count', 10000)}")
                except (ValueError, TypeError):
                    errors.append("page_count must be a valid integer")
        
        elif webhook_type == 'notes':
            priority = metadata.get('priority')
            if priority and priority not in rules.get('allowed_priorities', []):
                errors.append(f"Invalid priority: {priority}")
            
            category = metadata.get('category')
            if category and category not in rules.get('allowed_categories', []):
                errors.append(f"Invalid category: {category}")
            
            tags = metadata.get('tags', [])
            if isinstance(tags, list):
                if len(tags) > rules.get('max_tags_count', 20):
                    errors.append(f"Too many tags (max {rules.get('max_tags_count', 20)})")
                for tag in tags:
                    if len(str(tag)) > rules.get('max_tag_length', 50):
                        errors.append(f"Tag too long: {tag} (max {rules.get('max_tag_length', 50)} characters)")
        
        elif webhook_type == 'documents':
            doc_type = metadata.get('document_type')
            if doc_type and doc_type not in rules.get('allowed_document_types', []):
                errors.append(f"Invalid document_type: {doc_type}")
            
            classification = metadata.get('classification')
            if classification and classification not in rules.get('allowed_classifications', []):
                errors.append(f"Invalid classification: {classification}")
            
            version = metadata.get('version')
            if version and not re.match(rules.get('version_pattern', r'^\d+\.\d+$'), version):
                errors.append(f"Invalid version format: {version}")
        
        elif webhook_type == 'videos':
            resolution = metadata.get('resolution')
            if resolution and resolution not in rules.get('allowed_resolutions', []):
                errors.append(f"Invalid resolution: {resolution}")
            
            format_type = metadata.get('format')
            if format_type and format_type not in rules.get('allowed_formats', []):
                errors.append(f"Invalid video format: {format_type}")
            
            fps = metadata.get('fps')
            if fps is not None:
                try:
                    fps = int(fps)
                    if fps < rules.get('min_fps', 1) or fps > rules.get('max_fps', 120):
                        errors.append(f"Invalid fps: must be between {rules.get('min_fps', 1)} and {rules.get('max_fps', 120)}")
                except (ValueError, TypeError):
                    errors.append("fps must be a valid integer")
        
        elif webhook_type == 'images':
            format_type = metadata.get('format')
            if format_type and format_type not in rules.get('allowed_formats', []):
                errors.append(f"Invalid image format: {format_type}")
            
            dimensions = metadata.get('dimensions')
            if dimensions and not re.match(rules.get('dimension_pattern', r'^\d+x\d+$'), dimensions):
                errors.append(f"Invalid dimensions format: {dimensions} (use format: WIDTHxHEIGHT)")
        
        elif webhook_type == 'meetings':
            meeting_type = metadata.get('meeting_type')
            if meeting_type and meeting_type not in rules.get('allowed_meeting_types', []):
                errors.append(f"Invalid meeting_type: {meeting_type}")
            
            participants = metadata.get('participants', [])
            if isinstance(participants, list) and len(participants) > rules.get('max_participants_count', 100):
                errors.append(f"Too many participants (max {rules.get('max_participants_count', 100)})")
        
        return errors
    
    @classmethod
    def _validate_type_specific_fields(cls, webhook_type: str, type_specific: Dict[str, Any], rules: Dict[str, Any]) -> List[str]:
        """Validate type-specific fields"""
        errors = []
        
        if webhook_type == 'audio':
            duration = type_specific.get('duration')
            if duration is not None:
                try:
                    duration = float(duration)
                    if duration < rules.get('min_duration', 1) or duration > rules.get('max_duration', 7200):
                        errors.append(f"Invalid duration: must be between {rules.get('min_duration', 1)} and {rules.get('max_duration', 7200)} seconds")
                except (ValueError, TypeError):
                    errors.append("duration must be a valid number")
            
            format_type = type_specific.get('format')
            if format_type and format_type not in rules.get('allowed_formats', []):
                errors.append(f"Invalid audio format: {format_type}")
        
        elif webhook_type == 'lectures':
            slides_count = type_specific.get('slides_count')
            if slides_count is not None:
                try:
                    slides_count = int(slides_count)
                    if slides_count < rules.get('min_slides_count', 1) or slides_count > rules.get('max_slides_count', 1000):
                        errors.append(f"Invalid slides_count: must be between {rules.get('min_slides_count', 1)} and {rules.get('max_slides_count', 1000)}")
                except (ValueError, TypeError):
                    errors.append("slides_count must be a valid integer")
        
        elif webhook_type == 'podcasts':
            episode_number = type_specific.get('episode_number')
            if episode_number is not None:
                try:
                    episode_number = int(episode_number)
                    if episode_number < 1 or episode_number > rules.get('max_episode_number', 10000):
                        errors.append(f"Invalid episode_number: must be between 1 and {rules.get('max_episode_number', 10000)}")
                except (ValueError, TypeError):
                    errors.append("episode_number must be a valid integer")
        
        elif webhook_type == 'research':
            keywords = type_specific.get('keywords', [])
            if isinstance(keywords, list) and len(keywords) > rules.get('max_keywords_count', 15):
                errors.append(f"Too many keywords (max {rules.get('max_keywords_count', 15)})")
        
        return errors
    
    @classmethod
    def sanitize_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize payload by removing/fixing common issues"""
        sanitized = payload.copy()
        
        # Ensure timestamp is present
        if 'timestamp' not in sanitized:
            sanitized['timestamp'] = datetime.now().isoformat()
        
        # Ensure user_info has required fields
        if 'user_info' not in sanitized:
            sanitized['user_info'] = {}
        if 'name' not in sanitized['user_info']:
            sanitized['user_info']['name'] = 'Anonymous User'
        
        # Ensure content structure
        if 'content' not in sanitized:
            sanitized['content'] = {}
        if 'metadata' not in sanitized['content']:
            sanitized['content']['metadata'] = {}
        if 'type_specific_fields' not in sanitized['content']:
            sanitized['content']['type_specific_fields'] = {}
        
        # Trim string fields
        def trim_strings(obj, max_length=1000):
            if isinstance(obj, dict):
                return {k: trim_strings(v, max_length) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [trim_strings(item, max_length) for item in obj]
            elif isinstance(obj, str):
                return obj[:max_length] if len(obj) > max_length else obj
            else:
                return obj
        
        # Apply string trimming to metadata
        sanitized['content']['metadata'] = trim_strings(sanitized['content']['metadata'])
        
        return sanitized

# Error handling utilities
class WebhookError(Exception):
    """Base webhook error"""
    pass

class ValidationError(WebhookError):
    """Validation specific error"""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(f"Validation failed: {'; '.join(errors)}")

class PayloadTooLargeError(WebhookError):
    """Payload size error"""
    pass

class RateLimitError(WebhookError):
    """Rate limiting error"""
    pass

def create_error_response(error_type: str, message: str, details: Optional[Dict] = None) -> Dict[str, Any]:
    """Create standardized error response"""
    return {
        'error': True,
        'error_type': error_type,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'details': details or {}
    }

def log_webhook_error(webhook_type: str, error: Exception, payload_size: int = 0) -> None:
    """Log webhook errors for monitoring"""
    error_data = {
        'timestamp': datetime.now().isoformat(),
        'webhook_type': webhook_type,
        'error_type': type(error).__name__,
        'error_message': str(error),
        'payload_size': payload_size
    }
    
    # In a real application, this would write to a proper logging system
    print(f"WEBHOOK_ERROR: {json.dumps(error_data)}")

# Rate limiting utilities
class RateLimiter:
    """Simple rate limiter for webhook requests"""
    
    def __init__(self):
        self.requests = {}
        self.limits = {
            'per_minute': 60,
            'per_hour': 1000,
            'per_day': 10000
        }
    
    def check_rate_limit(self, user_id: str, webhook_type: str) -> Tuple[bool, str]:
        """Check if request is within rate limits"""
        now = datetime.now()
        key = f"{user_id}:{webhook_type}"
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if (now - req_time).total_seconds() < 86400  # Keep last 24 hours
        ]
        
        # Check limits
        recent_requests = self.requests[key]
        
        # Per minute check
        minute_ago = now.timestamp() - 60
        minute_count = len([r for r in recent_requests if r.timestamp() > minute_ago])
        if minute_count >= self.limits['per_minute']:
            return False, "Rate limit exceeded: too many requests per minute"
        
        # Per hour check
        hour_ago = now.timestamp() - 3600
        hour_count = len([r for r in recent_requests if r.timestamp() > hour_ago])
        if hour_count >= self.limits['per_hour']:
            return False, "Rate limit exceeded: too many requests per hour"
        
        # Per day check
        if len(recent_requests) >= self.limits['per_day']:
            return False, "Rate limit exceeded: too many requests per day"
        
        # Add current request
        self.requests[key].append(now)
        
        return True, "Within rate limits"

# Global rate limiter instance
rate_limiter = RateLimiter()

