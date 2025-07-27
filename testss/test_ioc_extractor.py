
## tests for ioc_extractor.py module ##


import pytest
from unittest.mock import patch, Mock
from ioc_extractor import extract_ips, extract_domains, extract_hashes


class TestIPExtraction:
    """Test IP address extraction functionality"""
    
    def test_extract_ips_basic(self):
        """Test basic IP extraction from logs"""
        logs = [
            {
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1 port 22",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "raw_log": "Jul 20 10:00:01 host sshd[1235]: Connection from 10.0.0.5 port 54321",
                "timestamp": None,
                "source_ip": "10.0.0.5",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_ips(logs)
        assert len(result) == 2
        
        ips = [entry['ip'] for entry in result]
        assert '192.168.1.1' in ips
        assert '10.0.0.5' in ips
        
        # Check structure
        for entry in result:
            assert 'ip' in entry
            assert 'enrichment' in entry
            assert isinstance(entry['enrichment'], dict)
    
    def test_extract_ips_duplicates(self):
        """Test that duplicate IPs are not included multiple times"""
        logs = [
            {
                "raw_log": "Jul 20 10:00:00 host sshd[1234]: Failed password for user from 192.168.1.1 port 22",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "raw_log": "Jul 20 10:00:01 host sshd[1235]: Failed password for user from 192.168.1.1 port 22",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_ips(logs)
        assert len(result) == 1
        assert result[0]['ip'] == '192.168.1.1'
    
    def test_extract_ips_no_ips(self):
        """Test extraction when no IPs are present"""
        logs = [
            {
                "raw_log": "Jul 20 10:00:00 host kernel: Some kernel message without IP",
                "timestamp": None,
                "source_ip": "N/A",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_ips(logs)
        assert len(result) == 0
    
    def test_extract_ips_multiple_ips_per_log(self):
        """Test extraction when multiple IPs are in a single log line"""
        logs = [
            {
                "raw_log": "Connection from 192.168.1.1 to 10.0.0.5 established",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_ips(logs)
        assert len(result) == 2
        
        ips = [entry['ip'] for entry in result]
        assert '192.168.1.1' in ips
        assert '10.0.0.5' in ips
    
    @patch('ioc_extractor.requests.get')
    def test_extract_ips_with_abuseipdb_success(self, mock_get):
        """Test IP extraction with successful AbuseIPDB enrichment"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 75,
                "countryCode": "US",
                "isPublic": True
            }
        }
        mock_get.return_value = mock_response
        
        logs = [
            {
                "raw_log": "Connection from 192.168.1.1",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_ips(logs, abuseipdb_key="test_api_key")
        assert len(result) == 1
        assert result[0]['ip'] == '192.168.1.1'
        assert 'abuseipdb' in result[0]['enrichment']
        assert result[0]['enrichment']['abuseipdb']['abuseConfidenceScore'] == 75
        
        # Verify API was called correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert 'ipAddress=192.168.1.1' in call_args[0][0]
        assert call_args[1]['headers']['Key'] == 'test_api_key'
    
    @patch('ioc_extractor.requests.get')
    def test_extract_ips_with_abuseipdb_failure(self, mock_get):
        """Test IP extraction with failed AbuseIPDB enrichment"""
        # Mock failed API response
        mock_get.side_effect = Exception("API Error")
        
        logs = [
            {
                "raw_log": "Connection from 192.168.1.1",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_ips(logs, abuseipdb_key="test_api_key")
        assert len(result) == 1
        assert result[0]['ip'] == '192.168.1.1'
        assert result[0]['enrichment'] == {}  # No enrichment due to API failure


class TestDomainExtraction:
    """Test domain extraction functionality"""
    
    def test_extract_domains_basic(self):
        """Test basic domain extraction from logs"""
        logs = [
            {
                "raw_log": "DNS query for example.com from client",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "raw_log": "HTTP request to malicious.domain.org",
                "timestamp": None,
                "source_ip": "192.168.1.2",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_domains(logs)
        assert len(result) == 2
        assert 'example.com' in result
        assert 'malicious.domain.org' in result
        assert isinstance(result, list)
        assert result == sorted(result)  # Should be sorted
    
    def test_extract_domains_duplicates(self):
        """Test that duplicate domains are not included multiple times"""
        logs = [
            {
                "raw_log": "First request to example.com",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "raw_log": "Second request to example.com",
                "timestamp": None,
                "source_ip": "192.168.1.2",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_domains(logs)
        assert len(result) == 1
        assert result[0] == 'example.com'
    
    def test_extract_domains_exclude_ips(self):
        """Test that IP addresses are not included as domains"""
        logs = [
            {
                "raw_log": "Connection to 192.168.1.1 and example.com",
                "timestamp": None,
                "source_ip": "192.168.1.2",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_domains(logs)
        assert len(result) == 1
        assert result[0] == 'example.com'
        assert '192.168.1.1' not in result
    
    def test_extract_domains_no_domains(self):
        """Test extraction when no domains are present"""
        logs = [
            {
                "raw_log": "Some log message without any domains or IPs",
                "timestamp": None,
                "source_ip": "N/A",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_domains(logs)
        assert len(result) == 0
    
    def test_extract_domains_various_tlds(self):
        """Test extraction of domains with various TLDs"""
        logs = [
            {
                "raw_log": "Requests to test.com, example.org, site.net, domain.info, and malware.xyz",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_domains(logs)
        expected_domains = ['domain.info', 'example.org', 'malware.xyz', 'site.net', 'test.com']
        assert result == expected_domains


class TestHashExtraction:
    """Test hash extraction functionality"""
    
    def test_extract_hashes_md5(self):
        """Test extraction of MD5 hashes"""
        logs = [
            {
                "raw_log": "File hash: 5d41402abc4b2a76b9719d911017c592",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs)
        assert len(result) == 1
        assert result[0]['hash'] == '5d41402abc4b2a76b9719d911017c592'
        assert 'enrichment' in result[0]
    
    def test_extract_hashes_sha1(self):
        """Test extraction of SHA1 hashes"""
        logs = [
            {
                "raw_log": "SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs)
        assert len(result) == 1
        assert result[0]['hash'] == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d'
    
    def test_extract_hashes_sha256(self):
        """Test extraction of SHA256 hashes"""
        logs = [
            {
                "raw_log": "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs)
        assert len(result) == 1
        assert result[0]['hash'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    
    def test_extract_hashes_multiple_types(self):
        """Test extraction of multiple hash types in one log"""
        logs = [
            {
                "raw_log": "MD5: 5d41402abc4b2a76b9719d911017c592 SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs)
        assert len(result) == 2
        
        hashes = [entry['hash'] for entry in result]
        assert '5d41402abc4b2a76b9719d911017c592' in hashes
        assert 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' in hashes
    
    def test_extract_hashes_duplicates(self):
        """Test that duplicate hashes are not included multiple times"""
        logs = [
            {
                "raw_log": "Hash: 5d41402abc4b2a76b9719d911017c592",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            },
            {
                "raw_log": "Same hash again: 5d41402abc4b2a76b9719d911017c592",
                "timestamp": None,
                "source_ip": "192.168.1.2",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs)
        assert len(result) == 1
        assert result[0]['hash'] == '5d41402abc4b2a76b9719d911017c592'
    
    def test_extract_hashes_no_hashes(self):
        """Test extraction when no hashes are present"""
        logs = [
            {
                "raw_log": "Some log message without any hashes",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs)
        assert len(result) == 0
    
    @patch('ioc_extractor.requests.get')
    def test_extract_hashes_with_virustotal_success(self, mock_get):
        """Test hash extraction with successful VirusTotal enrichment"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 60,
                        "harmless": 0
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        logs = [
            {
                "raw_log": "File hash: 5d41402abc4b2a76b9719d911017c592",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs, virustotal_key="test_api_key")
        assert len(result) == 1
        assert result[0]['hash'] == '5d41402abc4b2a76b9719d911017c592'
        assert 'virustotal' in result[0]['enrichment']
        
        # Verify API was called correctly
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert '5d41402abc4b2a76b9719d911017c592' in call_args[0][0]
        assert call_args[1]['headers']['x-apikey'] == 'test_api_key'
    
    @patch('ioc_extractor.requests.get')
    def test_extract_hashes_with_virustotal_failure(self, mock_get):
        """Test hash extraction with failed VirusTotal enrichment"""
        # Mock failed API response
        mock_get.side_effect = Exception("API Error")
        
        logs = [
            {
                "raw_log": "File hash: 5d41402abc4b2a76b9719d911017c592",
                "timestamp": None,
                "source_ip": "192.168.1.1",
                "log_type": "auth.log"
            }
        ]
        
        result = extract_hashes(logs, virustotal_key="test_api_key")
        assert len(result) == 1
        assert result[0]['hash'] == '5d41402abc4b2a76b9719d911017c592'
        assert result[0]['enrichment'] == {}  # No enrichment due to API failure


if __name__ == "__main__":
    pytest.main([__file__])

