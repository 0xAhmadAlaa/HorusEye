## Unit tests for parser.py module ##


import pytest
import tempfile
import os
from datetime import datetime
from parser import detect_log_format, parse_auth_log, parse_apache_log, parse_json_log, is_json


class TestLogFormatDetection:
    """Test log format detection functionality"""
    
    def test_detect_auth_log_format(self):
        """Test detection of auth.log format"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Jul 20 10:00:00 hostname sshd[1234]: Failed password for user from 192.168.1.1\n")
            f.write("Jul 20 10:00:01 hostname sudo[1235]: user : TTY=pts/0 ; PWD=/home/user ; USER=root\n")
            temp_path = f.name
        
        try:
            result = detect_log_format(temp_path)
            assert result == "auth.log"
        finally:
            os.unlink(temp_path)
    
    def test_detect_apache_log_format(self):
        """Test detection of Apache log format"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('192.168.1.1 - - [20/Jul/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 1234\n')
            f.write('192.168.1.2 - - [20/Jul/2025:10:00:01 +0000] "POST /login HTTP/1.1" 302 567\n')
            temp_path = f.name
        
        try:
            result = detect_log_format(temp_path)
            assert result == "apache"
        finally:
            os.unlink(temp_path)
    
    def test_detect_json_log_format(self):
        """Test detection of JSON log format"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('{"timestamp": "2025-07-20T10:00:00Z", "source_ip": "192.168.1.1", "message": "test"}\n')
            f.write('{"timestamp": "2025-07-20T10:00:01Z", "source_ip": "192.168.1.2", "message": "test2"}\n')
            temp_path = f.name
        
        try:
            result = detect_log_format(temp_path)
            assert result == "json"
        finally:
            os.unlink(temp_path)
    
    def test_detect_unknown_format(self):
        """Test detection with unknown format returns None"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("This is not a recognized log format\n")
            f.write("Random text that doesn't match any pattern\n")
            temp_path = f.name
        
        try:
            result = detect_log_format(temp_path)
            assert result is None
        finally:
            os.unlink(temp_path)
    
    def test_detect_nonexistent_file(self):
        """Test detection with non-existent file returns None"""
        result = detect_log_format("/nonexistent/file.log")
        assert result is None


class TestJSONValidation:
    """Test JSON validation functionality"""
    
    def test_is_json_valid(self):
        """Test valid JSON string"""
        assert is_json('{"key": "value"}') is True
        assert is_json('{"timestamp": "2025-07-20T10:00:00Z", "ip": "192.168.1.1"}') is True
    
    def test_is_json_invalid(self):
        """Test invalid JSON string"""
        assert is_json('not json') is False
        assert is_json('{"invalid": json}') is False
        assert is_json('') is False


class TestAuthLogParsing:
    """Test auth.log parsing functionality"""
    
    def test_parse_auth_log_basic(self):
        """Test basic auth.log parsing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Jul 20 10:00:00 hostname sshd[1234]: Failed password for user from 192.168.1.1 port 22 ssh2\n")
            f.write("Jul 20 10:00:01 hostname sudo[1235]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash\n")
            temp_path = f.name
        
        try:
            entries = parse_auth_log(temp_path)
            assert len(entries) == 2
            
            # Check first entry
            assert entries[0]['source_ip'] == '192.168.1.1'
            assert entries[0]['log_type'] == 'auth.log'
            assert isinstance(entries[0]['timestamp'], datetime)
            assert 'Failed password' in entries[0]['raw_log']
            
            # Check second entry
            assert entries[1]['source_ip'] == 'N/A'  # No IP in sudo log
            assert entries[1]['log_type'] == 'auth.log'
            assert 'sudo' in entries[1]['raw_log']
        finally:
            os.unlink(temp_path)
    
    def test_parse_auth_log_empty_file(self):
        """Test parsing empty auth.log file"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_path = f.name
        
        try:
            entries = parse_auth_log(temp_path)
            assert len(entries) == 0
        finally:
            os.unlink(temp_path)
    
    def test_parse_auth_log_malformed_lines(self):
        """Test parsing auth.log with malformed lines"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Jul 20 10:00:00 hostname sshd[1234]: Failed password for user from 192.168.1.1\n")
            f.write("This is a malformed line that won't match\n")
            f.write("Jul 20 10:00:02 hostname sshd[1236]: Accepted password for user from 192.168.1.2\n")
            temp_path = f.name
        
        try:
            entries = parse_auth_log(temp_path)
            assert len(entries) == 2  # Only valid lines should be parsed
            assert entries[0]['source_ip'] == '192.168.1.1'
            assert entries[1]['source_ip'] == '192.168.1.2'
        finally:
            os.unlink(temp_path)


class TestApacheLogParsing:
    """Test Apache log parsing functionality"""
    
    def test_parse_apache_log_basic(self):
        """Test basic Apache log parsing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('192.168.1.1 - - [20/Jul/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 1234\n')
            f.write('192.168.1.2 - - [20/Jul/2025:10:00:01 +0000] "POST /login HTTP/1.1" 404 567\n')
            temp_path = f.name
        
        try:
            entries = parse_apache_log(temp_path)
            assert len(entries) == 2
            
            # Check first entry
            assert entries[0]['source_ip'] == '192.168.1.1'
            assert entries[0]['log_type'] == 'apache'
            assert isinstance(entries[0]['timestamp'], datetime)
            assert 'GET /' in entries[0]['raw_log']
            
            # Check second entry
            assert entries[1]['source_ip'] == '192.168.1.2'
            assert entries[1]['log_type'] == 'apache'
            assert 'POST /login' in entries[1]['raw_log']
        finally:
            os.unlink(temp_path)
    
    def test_parse_apache_log_malformed_timestamp(self):
        """Test Apache log parsing with malformed timestamp"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('192.168.1.1 - - [invalid-timestamp] "GET / HTTP/1.1" 200 1234\n')
            temp_path = f.name
        
        try:
            entries = parse_apache_log(temp_path)
            assert len(entries) == 1
            assert entries[0]['timestamp'] is None  # Should handle invalid timestamp gracefully
            assert entries[0]['source_ip'] == '192.168.1.1'
        finally:
            os.unlink(temp_path)


class TestJSONLogParsing:
    """Test JSON log parsing functionality"""
    
    def test_parse_json_log_basic(self):
        """Test basic JSON log parsing"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('{"timestamp": "2025-07-20T10:00:00Z", "source_ip": "192.168.1.1", "message": "test1"}\n')
            f.write('{"timestamp": "2025-07-20T10:00:01Z", "source_ip": "192.168.1.2", "message": "test2"}\n')
            temp_path = f.name
        
        try:
            entries = parse_json_log(temp_path)
            assert len(entries) == 2
            
            # Check first entry
            assert entries[0]['source_ip'] == '192.168.1.1'
            assert entries[0]['log_type'] == 'json'
            assert isinstance(entries[0]['timestamp'], datetime)
            assert 'parsed_json' in entries[0]
            assert entries[0]['parsed_json']['message'] == 'test1'
            
            # Check second entry
            assert entries[1]['source_ip'] == '192.168.1.2'
            assert entries[1]['parsed_json']['message'] == 'test2'
        finally:
            os.unlink(temp_path)
    
    def test_parse_json_log_missing_fields(self):
        """Test JSON log parsing with missing fields"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('{"message": "test without timestamp or ip"}\n')
            f.write('{"timestamp": "2025-07-20T10:00:01Z", "message": "test without ip"}\n')
            temp_path = f.name
        
        try:
            entries = parse_json_log(temp_path)
            assert len(entries) == 2
            
            # Check first entry (missing timestamp and source_ip)
            assert entries[0]['source_ip'] == 'N/A'
            assert entries[0]['timestamp'] is None
            
            # Check second entry (missing source_ip)
            assert entries[1]['source_ip'] == 'N/A'
            assert isinstance(entries[1]['timestamp'], datetime)
        finally:
            os.unlink(temp_path)
    
    def test_parse_json_log_invalid_json(self):
        """Test JSON log parsing with invalid JSON lines"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('{"valid": "json"}\n')
            f.write('invalid json line\n')
            f.write('{"another": "valid json"}\n')
            temp_path = f.name
        
        try:
            entries = parse_json_log(temp_path)
            assert len(entries) == 2  # Only valid JSON lines should be parsed
            assert entries[0]['parsed_json']['valid'] == 'json'
            assert entries[1]['parsed_json']['another'] == 'valid json'
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__])

