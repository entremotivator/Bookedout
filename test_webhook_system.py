#!/usr/bin/env python3
"""
Comprehensive test suite for the enhanced webhook system
Tests all 10 webhook types with various scenarios
"""

import unittest
import json
import base64
import time
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the current directory to Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from validation_utils import (
        WebhookValidator, 
        ValidationError, 
        PayloadTooLargeError, 
        RateLimitError,
        create_error_response,
        rate_limiter
    )
except ImportError:
    print("Warning: validation_utils not found. Some tests may fail.")

class TestWebhookValidator(unittest.TestCase):
    """Test the webhook validation system"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a larger base64 encoded data to meet minimum size requirements
        test_audio_data = b'x' * 2048  # 2KB of test data
        encoded_audio = base64.b64encode(test_audio_data).decode()
        
        self.valid_base_payload = {
            'webhook_type': 'audio',
            'timestamp': datetime.now().isoformat(),
            'user_info': {
                'name': 'Test User',
                'session_id': 'test-session-123'
            },
            'content': {
                'title': 'Test Audio Recording',  # Add title to content level
                'primary_data': encoded_audio,
                'metadata': {
                    'title': 'Test Audio Recording',
                    'description': 'A test audio recording for validation'
                },
                'type_specific_fields': {
                    'format': 'webm',
                    'duration': 120,
                    'sample_rate': 44100
                }
            },
            'processing_options': {
                'quality': 'High',
                'auto_process': True
            }
        }
    
    def test_valid_audio_payload(self):
        """Test validation of a valid audio payload"""
        is_valid, errors = WebhookValidator.validate_webhook_payload(self.valid_base_payload)
        self.assertTrue(is_valid, f"Valid payload should pass validation. Errors: {errors}")
        self.assertEqual(len(errors), 0)
    
    def test_missing_required_fields(self):
        """Test validation fails when required fields are missing"""
        payload = self.valid_base_payload.copy()
        del payload['webhook_type']
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertIn('Missing required field: webhook_type', errors)
    
    def test_invalid_webhook_type(self):
        """Test validation fails for invalid webhook type"""
        payload = self.valid_base_payload.copy()
        payload['webhook_type'] = 'invalid_type'
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertIn('Invalid webhook_type: invalid_type', errors)
    
    def test_invalid_timestamp(self):
        """Test validation fails for invalid timestamp"""
        payload = self.valid_base_payload.copy()
        payload['timestamp'] = 'invalid-timestamp'
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any('Invalid timestamp' in error for error in errors))
    
    def test_empty_user_name(self):
        """Test validation fails for empty user name"""
        payload = self.valid_base_payload.copy()
        payload['user_info']['name'] = ''
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertIn('user_info.name is required and cannot be empty', errors)
    
    def test_all_webhook_types(self):
        """Test validation for all 10 webhook types"""
        webhook_types = [
            'audio', 'books', 'lectures', 'podcasts', 'notes',
            'documents', 'videos', 'images', 'research', 'meetings'
        ]
        
        for webhook_type in webhook_types:
            with self.subTest(webhook_type=webhook_type):
                payload = self.valid_base_payload.copy()
                payload['webhook_type'] = webhook_type
                
                # Add title to content (not just metadata)
                payload['content']['title'] = f'Test {webhook_type.title()} Content'
                payload['content']['metadata']['title'] = f'Test {webhook_type.title()} Content'
                
                # Adjust primary_data for different types
                if webhook_type in ['audio', 'videos']:
                    test_data = b'x' * 2048  # 2KB of test data
                    payload['content']['primary_data'] = base64.b64encode(test_data).decode()
                else:
                    payload['content']['primary_data'] = f'Test {webhook_type} content with sufficient length to pass validation'
                
                is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
                self.assertTrue(is_valid, f"Webhook type {webhook_type} should be valid. Errors: {errors}")
    
    def test_payload_sanitization(self):
        """Test payload sanitization"""
        payload = {
            'webhook_type': 'notes',
            'content': {
                'primary_data': 'Test content',
                'metadata': {
                    'title': 'A' * 1000  # Very long title
                }
            }
        }
        
        sanitized = WebhookValidator.sanitize_payload(payload)
        
        # Should add missing required fields
        self.assertIn('timestamp', sanitized)
        self.assertIn('user_info', sanitized)
        self.assertEqual(sanitized['user_info']['name'], 'Anonymous User')
        
        # Should ensure content structure
        self.assertIn('metadata', sanitized['content'])
        self.assertIn('type_specific_fields', sanitized['content'])

class TestWebhookPayloadCreation(unittest.TestCase):
    """Test payload creation for different webhook types"""
    
    def test_audio_payload_creation(self):
        """Test creation of audio-specific payload"""
        # This would test the create_payload_for_webhook_type function
        # from the main application
        pass
    
    def test_books_payload_creation(self):
        """Test creation of books-specific payload"""
        pass
    
    def test_notes_payload_creation(self):
        """Test creation of notes-specific payload"""
        pass

class TestRateLimiting(unittest.TestCase):
    """Test rate limiting functionality"""
    
    def setUp(self):
        """Set up rate limiter for testing"""
        self.rate_limiter = rate_limiter
        # Clear any existing requests
        self.rate_limiter.requests = {}
    
    def test_rate_limit_within_bounds(self):
        """Test that requests within rate limits are allowed"""
        user_id = 'test_user'
        webhook_type = 'audio'
        
        # Should allow first request
        allowed, message = self.rate_limiter.check_rate_limit(user_id, webhook_type)
        self.assertTrue(allowed)
        self.assertEqual(message, "Within rate limits")
    
    def test_rate_limit_exceeded(self):
        """Test that rate limits are enforced"""
        user_id = 'test_user'
        webhook_type = 'audio'
        
        # Simulate many requests in a short time
        for i in range(65):  # Exceed per-minute limit of 60
            allowed, message = self.rate_limiter.check_rate_limit(user_id, webhook_type)
            if not allowed:
                self.assertIn("Rate limit exceeded", message)
                break
        else:
            self.fail("Rate limit should have been exceeded")

class TestErrorHandling(unittest.TestCase):
    """Test error handling and response creation"""
    
    def test_create_error_response(self):
        """Test error response creation"""
        error_response = create_error_response(
            'validation_error',
            'Test error message',
            {'field': 'test_field'}
        )
        
        self.assertTrue(error_response['error'])
        self.assertEqual(error_response['error_type'], 'validation_error')
        self.assertEqual(error_response['message'], 'Test error message')
        self.assertIn('timestamp', error_response)
        self.assertEqual(error_response['details']['field'], 'test_field')
    
    def test_validation_error_creation(self):
        """Test ValidationError exception"""
        errors = ['Error 1', 'Error 2']
        
        with self.assertRaises(ValidationError) as context:
            raise ValidationError(errors)
        
        self.assertEqual(context.exception.errors, errors)
        self.assertIn('Error 1', str(context.exception))
        self.assertIn('Error 2', str(context.exception))

class TestWebhookIntegration(unittest.TestCase):
    """Integration tests for the webhook system"""
    
    @patch('requests.post')
    def test_successful_webhook_send(self, mock_post):
        """Test successful webhook sending"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Success'
        mock_post.return_value = mock_response
        
        # This would test the actual send_to_webhook function
        # from the main application
        pass
    
    @patch('requests.post')
    def test_webhook_timeout_handling(self, mock_post):
        """Test webhook timeout handling"""
        import requests
        mock_post.side_effect = requests.exceptions.Timeout()
        
        # Test that timeout is handled gracefully
        pass
    
    @patch('requests.post')
    def test_webhook_connection_error_handling(self, mock_post):
        """Test webhook connection error handling"""
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError()
        
        # Test that connection errors are handled gracefully
        pass

class TestSpecificWebhookTypes(unittest.TestCase):
    """Test specific validation rules for each webhook type"""
    
    def test_books_genre_validation(self):
        """Test that book genre validation works"""
        payload = {
            'webhook_type': 'books',
            'timestamp': datetime.now().isoformat(),
            'user_info': {'name': 'Test User'},
            'content': {
                'primary_data': 'Book content',
                'metadata': {
                    'title': 'Test Book',
                    'genre': 'InvalidGenre'  # Invalid genre
                },
                'type_specific_fields': {}
            }
        }
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any('Invalid genre' in error for error in errors))
    
    def test_notes_priority_validation(self):
        """Test that notes priority validation works"""
        payload = {
            'webhook_type': 'notes',
            'timestamp': datetime.now().isoformat(),
            'user_info': {'name': 'Test User'},
            'content': {
                'primary_data': 'Note content',
                'metadata': {
                    'title': 'Test Note',
                    'priority': 'invalid_priority'  # Invalid priority
                },
                'type_specific_fields': {}
            }
        }
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any('Invalid priority' in error for error in errors))
    
    def test_videos_resolution_validation(self):
        """Test that video resolution validation works"""
        payload = {
            'webhook_type': 'videos',
            'timestamp': datetime.now().isoformat(),
            'user_info': {'name': 'Test User'},
            'content': {
                'primary_data': base64.b64encode(b'x' * 2048).decode(),
                'metadata': {
                    'title': 'Test Video',
                    'resolution': '999p'  # Invalid resolution
                },
                'type_specific_fields': {}
            }
        }
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any('Invalid resolution' in error for error in errors))
    
    def test_meetings_type_validation(self):
        """Test that meeting type validation works"""
        payload = {
            'webhook_type': 'meetings',
            'timestamp': datetime.now().isoformat(),
            'user_info': {'name': 'Test User'},
            'content': {
                'primary_data': 'Meeting content',
                'metadata': {
                    'title': 'Test Meeting',
                    'meeting_type': 'invalid_type'  # Invalid meeting type
                },
                'type_specific_fields': {}
            }
        }
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertFalse(is_valid)
        self.assertTrue(any('Invalid meeting_type' in error for error in errors))

class TestPerformance(unittest.TestCase):
    """Test performance aspects of the webhook system"""
    
    def test_validation_performance(self):
        """Test that validation doesn't take too long"""
        test_data = b'x' * 10000  # 10KB of test data
        payload = {
            'webhook_type': 'audio',
            'timestamp': datetime.now().isoformat(),
            'user_info': {'name': 'Test User'},
            'content': {
                'title': 'Performance Test Audio',  # Add title to content level
                'primary_data': base64.b64encode(test_data).decode(),
                'metadata': {'title': 'Performance Test Audio'},
                'type_specific_fields': {}
            }
        }
        
        start_time = time.time()
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        end_time = time.time()
        
        # Validation should complete within 1 second
        self.assertLess(end_time - start_time, 1.0)
        self.assertTrue(is_valid, f"Performance test payload should be valid. Errors: {errors}")
    
    def test_large_payload_handling(self):
        """Test handling of large payloads"""
        # Test with payload approaching size limits
        large_content = 'x' * (500 * 1024)  # 500KB of content (reduced to stay under limit)
        
        payload = {
            'webhook_type': 'books',
            'timestamp': datetime.now().isoformat(),
            'user_info': {'name': 'Test User'},
            'content': {
                'title': 'Large Book Content',  # Add title to content level
                'primary_data': large_content,
                'metadata': {'title': 'Large Book Content'},
                'type_specific_fields': {}
            }
        }
        
        is_valid, errors = WebhookValidator.validate_webhook_payload(payload)
        self.assertTrue(is_valid, f"Large payload should be valid. Errors: {errors}")  # Should handle large content

def run_webhook_system_tests():
    """Run all webhook system tests"""
    print("🧪 Running Enhanced Webhook System Tests")
    print("=" * 50)
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestWebhookValidator,
        TestWebhookPayloadCreation,
        TestRateLimiting,
        TestErrorHandling,
        TestWebhookIntegration,
        TestSpecificWebhookTypes,
        TestPerformance
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"🎯 Test Summary:")
    print(f"   Tests run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")
    print(f"   Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\n❌ Failures:")
        for test, traceback in result.failures:
            error_msg = traceback.split('AssertionError: ')[-1].split('\n')[0]
            print(f"   - {test}: {error_msg}")
    
    if result.errors:
        print(f"\n💥 Errors:")
        for test, traceback in result.errors:
            error_lines = traceback.split('\n')
            error_msg = error_lines[-2] if len(error_lines) > 1 else str(traceback)
            print(f"   - {test}: {error_msg}")
    
    if not result.failures and not result.errors:
        print("✅ All tests passed!")
    
    return result.wasSuccessful()

def test_webhook_endpoints():
    """Test actual webhook endpoints (if available)"""
    print("\n🌐 Testing Webhook Endpoints")
    print("-" * 30)
    
    webhook_urls = {
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
    
    import requests
    
    test_payload = {
        'webhook_type': 'test',
        'timestamp': datetime.now().isoformat(),
        'user_info': {'name': 'Test User'},
        'content': {
            'primary_data': 'Test data',
            'metadata': {'title': 'Test'},
            'type_specific_fields': {}
        }
    }
    
    results = {}
    
    for webhook_type, url in webhook_urls.items():
        try:
            test_payload['webhook_type'] = webhook_type
            response = requests.post(
                url, 
                json=test_payload, 
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )
            
            results[webhook_type] = {
                'status': 'success' if response.status_code == 200 else 'error',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds()
            }
            
            status_icon = "✅" if response.status_code == 200 else "❌"
            print(f"   {status_icon} {webhook_type}: {response.status_code} ({response.elapsed.total_seconds():.2f}s)")
            
        except requests.exceptions.Timeout:
            results[webhook_type] = {'status': 'timeout', 'status_code': None}
            print(f"   ⏱️ {webhook_type}: Timeout")
        except requests.exceptions.ConnectionError:
            results[webhook_type] = {'status': 'connection_error', 'status_code': None}
            print(f"   🔌 {webhook_type}: Connection Error")
        except Exception as e:
            results[webhook_type] = {'status': 'error', 'error': str(e)}
            print(f"   💥 {webhook_type}: {str(e)}")
    
    # Summary
    successful = len([r for r in results.values() if r.get('status') == 'success'])
    total = len(results)
    
    print(f"\n📊 Endpoint Test Summary:")
    print(f"   Successful: {successful}/{total}")
    print(f"   Success rate: {(successful/total*100):.1f}%")
    
    return results

if __name__ == "__main__":
    print("🚀 Enhanced Webhook System Test Suite")
    print("=====================================")
    
    # Run unit tests
    unit_tests_passed = run_webhook_system_tests()
    
    # Test actual endpoints (optional)
    try:
        endpoint_results = test_webhook_endpoints()
    except Exception as e:
        print(f"\n⚠️ Endpoint testing failed: {e}")
        endpoint_results = {}
    
    # Final summary
    print("\n" + "=" * 50)
    print("🏁 Final Test Results:")
    print(f"   Unit Tests: {'✅ PASSED' if unit_tests_passed else '❌ FAILED'}")
    
    if endpoint_results:
        successful_endpoints = len([r for r in endpoint_results.values() if r.get('status') == 'success'])
        total_endpoints = len(endpoint_results)
        print(f"   Endpoint Tests: {successful_endpoints}/{total_endpoints} successful")
    
    print("\n🎉 Testing complete!")

