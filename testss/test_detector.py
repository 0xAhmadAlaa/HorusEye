## tests for detector.py module ##


import pytest
import tempfile
import os
import json
from datetime import datetime, timedelta
from detector import load_rules, detect_events, RuleError


class TestRuleLoading:
    """Test rule loading functionality"""
    
    def test_load_valid_rules(self):
        """Test loading valid rules from JSON file"""
        rules_data = [
            {
                "name": "Test Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 3,
                "priority": "high",
                "enabled": True,
                "mitre_attack": "T1110.001"
            },
            {
                "name": "Test Rule 2",
                "log_type": "apache",
                "pattern_type": "regex",
                "pattern": r"\" 404 ",
                "threshold": 1,
                "priority": "medium",
                "enabled": True
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            temp_path = f.name
        
        try:
            rules = load_rules(temp_path)
            assert len(rules) == 2
            assert rules[0]['name'] == "Test Rule"
            assert rules[0]['threshold'] == 3
            assert rules[1]['name'] == "Test Rule 2"
            assert rules[1]['pattern_type'] == "regex"
        finally:
            os.unlink(temp_path)
    
    def test_load_rules_with_disabled(self):
        """Test loading rules with some disabled"""
        rules_data = [
            {
                "name": "Enabled Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 3,
                "priority": "high",
                "enabled": True
            },
            {
                "name": "Disabled Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Test pattern",
                "threshold": 1,
                "priority": "low",
                "enabled": False
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            temp_path = f.name
        
        try:
            rules = load_rules(temp_path)
            assert len(rules) == 1  # Only enabled rules should be returned
            assert rules[0]['name'] == "Enabled Rule"
        finally:
            os.unlink(temp_path)
    
    def test_load_rules_missing_required_fields(self):
        """Test loading rules with missing required fields raises RuleError"""
        rules_data = [
            {
                "name": "Incomplete Rule",
                "log_type": "auth.log",
                # Missing pattern_type, pattern, threshold, priority, enabled
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(RuleError):
                load_rules(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_load_rules_invalid_pattern_type(self):
        """Test loading rules with invalid pattern_type raises RuleError"""
        rules_data = [
            {
                "name": "Invalid Pattern Type Rule",
                "log_type": "auth.log",
                "pattern_type": "invalid_type",  # Should be 'keyword' or 'regex'
                "pattern": "test",
                "threshold": 1,
                "priority": "low",
                "enabled": True
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(RuleError):
                load_rules(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_load_rules_invalid_enabled_type(self):
        """Test loading rules with non-boolean enabled field raises RuleError"""
        rules_data = [
            {
                "name": "Invalid Enabled Type Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "test",
                "threshold": 1,
                "priority": "low",
                "enabled": "true"  # Should be boolean, not string
            }
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(rules_data, f)
            temp_path = f.name
        
        try:
            with pytest.raises(RuleError):
                load_rules(temp_path)
        finally:
            os.unlink(temp_path)
    
    def test_load_rules_nonexistent_file(self):
        """Test loading rules from non-existent file raises RuleError"""
        with pytest.raises(RuleError):
            load_rules("/nonexistent/rules.json")
    
    def test_load_rules_invalid_json(self):
        """Test loading rules from invalid JSON file raises RuleError"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_path = f.name
        
        try:
            with pytest.raises(RuleError):
                load_rules(temp_path)
        finally:
            os.unlink(temp_path)


class TestEventDetection:
    """Test event detection functionality"""
    
    def test_detect_events_keyword_match(self):
        """Test event detection with keyword pattern"""
        rules = [
            {
                "name": "SSH Brute Force",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 2,
                "priority": "high",
                "enabled": True,
                "mitre_attack": "T1110.001"
            }
        ]
        
        logs = [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:01 host sshd[1235]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.2",
                "raw_log": "Jul 20 10:00:02 host sshd[1236]: Accepted password for user from 192.168.1.2",
                "log_type": "auth.log"
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 1
        assert detections[0]['rule_name'] == "SSH Brute Force"
        assert detections[0]['count'] == 2
        assert detections[0]['priority'] == "high"
        assert detections[0]['mitre_attack'] == "T1110.001"
        assert len(detections[0]['matching_logs']) == 2
    
    def test_detect_events_regex_match(self):
        """Test event detection with regex pattern"""
        rules = [
            {
                "name": "Apache 404 Errors",
                "log_type": "apache",
                "pattern_type": "regex",
                "pattern": r"\" 404 ",
                "threshold": 1,
                "priority": "medium",
                "enabled": True
            }
        ]
        
        logs = [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": '192.168.1.1 - - [20/Jul/2025:10:00:00 +0000] "GET /nonexistent HTTP/1.1" 404 1234',
                "log_type": "apache"
            },
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.2",
                "raw_log": '192.168.1.2 - - [20/Jul/2025:10:00:01 +0000] "GET / HTTP/1.1" 200 5678',
                "log_type": "apache"
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 1
        assert detections[0]['rule_name'] == "Apache 404 Errors"
        assert detections[0]['count'] == 1
        assert detections[0]['priority'] == "medium"
        assert len(detections[0]['matching_logs']) == 1
    
    def test_detect_events_below_threshold(self):
        """Test that events below threshold are not detected"""
        rules = [
            {
                "name": "High Threshold Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 5,  # High threshold
                "priority": "high",
                "enabled": True
            }
        ]
        
        logs = [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:01 host sshd[1235]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 0  # Below threshold, no detection
    
    def test_detect_events_wrong_log_type(self):
        """Test that rules don't match logs of different types"""
        rules = [
            {
                "name": "Auth Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 1,
                "priority": "high",
                "enabled": True
            }
        ]
        
        logs = [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": '192.168.1.1 - - [20/Jul/2025:10:00:00 +0000] "GET /Failed password HTTP/1.1" 200 1234',
                "log_type": "apache"  # Different log type
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 0  # Wrong log type, no detection
    
    def test_detect_events_with_time_window(self):
        """Test event detection with time window constraint"""
        base_time = datetime.now()
        
        rules = [
            {
                "name": "Time Window Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 3,
                "window_seconds": 60,  # 1 minute window
                "priority": "high",
                "enabled": True
            }
        ]
        
        logs = [
            {
                "timestamp": base_time,
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": base_time + timedelta(seconds=30),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:30 host sshd[1235]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": base_time + timedelta(seconds=45),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:45 host sshd[1236]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 1  # All within time window
        assert detections[0]['count'] == 3
    
    def test_detect_events_outside_time_window(self):
        """Test that events outside time window are not detected"""
        base_time = datetime.now()
        
        rules = [
            {
                "name": "Strict Time Window Rule",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 3,
                "window_seconds": 30,  # 30 second window
                "priority": "high",
                "enabled": True
            }
        ]
        
        logs = [
            {
                "timestamp": base_time,
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": base_time + timedelta(seconds=15),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:15 host sshd[1235]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": base_time + timedelta(seconds=45),  # Outside 30s window
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:45 host sshd[1236]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 0  # Outside time window, no detection
    
    def test_detect_events_multiple_rules(self):
        """Test detection with multiple rules"""
        rules = [
            {
                "name": "SSH Failures",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Failed password",
                "threshold": 1,
                "priority": "high",
                "enabled": True
            },
            {
                "name": "SSH Success",
                "log_type": "auth.log",
                "pattern_type": "keyword",
                "pattern": "Accepted password",
                "threshold": 1,
                "priority": "medium",
                "enabled": True
            }
        ]
        
        logs = [
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.1",
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "timestamp": datetime.now(),
                "source_ip": "192.168.1.2",
                "raw_log": "Jul 20 10:00:01 host sshd[1235]: Accepted password for user from 192.168.1.2",
                "log_type": "auth.log"
            }
        ]
        
        detections = detect_events(logs, rules)
        assert len(detections) == 2
        rule_names = [d['rule_name'] for d in detections]
        assert "SSH Failures" in rule_names
        assert "SSH Success" in rule_names


if __name__ == "__main__":
    pytest.main([__file__])

