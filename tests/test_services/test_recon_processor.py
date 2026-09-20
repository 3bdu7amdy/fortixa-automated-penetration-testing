"""Tests for ReconProcessor."""
import os
import json
import pytest
import tempfile
from app.services.recon_processor import ReconProcessor


class TestReconProcessor:
    """Test suite for the ReconProcessor class."""

    def setup_method(self):
        self.processor = ReconProcessor()

    # ── process ──────────────────────────────────────────────────

    def test_process_collects_subdomains(self):
        """Process collects and deduplicates subdomains from tool outputs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create subfinder output
            subfinder_dir = os.path.join(tmpdir, 'subfinder')
            os.makedirs(subfinder_dir)
            with open(os.path.join(subfinder_dir, 'subfinder_output.txt'), 'w') as f:
                f.write("sub1.example.com\nsub2.example.com\nsub3.example.com\n")

            # Create assetfinder output with overlapping subdomain
            assetfinder_dir = os.path.join(tmpdir, 'assetfinder')
            os.makedirs(assetfinder_dir)
            with open(os.path.join(assetfinder_dir, 'assetfinder_output.txt'), 'w') as f:
                f.write("sub2.example.com\nsub4.example.com\n")

            result = self.processor.process(None, tmpdir)

            # Should have 4 unique subdomains
            assert result['stats']['total_subdomains'] == 4

            # Check subdomains.txt was written
            subdomains_file = os.path.join(tmpdir, 'subdomains.txt')
            assert os.path.exists(subdomains_file)
            with open(subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            assert len(subdomains) == 4

    def test_process_collects_urls(self):
        """Process collects and deduplicates URLs from tool outputs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create waybackurls output
            wayback_dir = os.path.join(tmpdir, 'waybackurls')
            os.makedirs(wayback_dir)
            with open(os.path.join(wayback_dir, 'waybackurls_output.txt'), 'w') as f:
                f.write("https://example.com/page1\nhttps://example.com/page2\n")

            # Create gau output with overlapping URL
            gau_dir = os.path.join(tmpdir, 'gau')
            os.makedirs(gau_dir)
            with open(os.path.join(gau_dir, 'gau_output.txt'), 'w') as f:
                f.write("https://example.com/page2\nhttps://example.com/page3\n")

            result = self.processor.process(None, tmpdir)

            # Should have 3 unique URLs
            assert result['stats']['total_urls'] == 3

            # Check all_urls.txt was written
            all_urls_file = os.path.join(tmpdir, 'all_urls.txt')
            assert os.path.exists(all_urls_file)

    def test_process_extracts_param_urls(self):
        """Process extracts URLs with query parameters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            wayback_dir = os.path.join(tmpdir, 'waybackurls')
            os.makedirs(wayback_dir)
            with open(os.path.join(wayback_dir, 'waybackurls_output.txt'), 'w') as f:
                f.write(
                    "https://example.com/page\n"
                    "https://example.com/search?q=test\n"
                    "https://example.com/api?id=1&name=foo\n"
                )

            result = self.processor.process(None, tmpdir)

            assert result['stats']['param_urls'] == 2

            # Check param_urls.txt
            param_file = os.path.join(tmpdir, 'param_urls.txt')
            assert os.path.exists(param_file)
            with open(param_file, 'r') as f:
                param_urls = [line.strip() for line in f if line.strip()]
            assert len(param_urls) == 2

    def test_process_extracts_interesting_extensions(self):
        """Process extracts URLs with interesting file extensions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            katana_dir = os.path.join(tmpdir, 'katana')
            os.makedirs(katana_dir)
            with open(os.path.join(katana_dir, 'katana_output.txt'), 'w') as f:
                f.write(
                    "https://example.com/app.js\n"
                    "https://example.com/index.php\n"
                    "https://example.com/page.html\n"
                    "https://example.com/login.asp\n"
                )

            result = self.processor.process(None, tmpdir)

            # .js, .php, .asp are interesting; .html is not
            assert result['stats']['interesting_urls'] == 3

    def test_process_detects_graphql_endpoints(self):
        """Process detects GraphQL endpoint URLs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            gau_dir = os.path.join(tmpdir, 'gau')
            os.makedirs(gau_dir)
            with open(os.path.join(gau_dir, 'gau_output.txt'), 'w') as f:
                f.write(
                    "https://example.com/graphql\n"
                    "https://example.com/api/graphql\n"
                    "https://example.com/graphiql\n"
                    "https://example.com/playground\n"
                    "https://example.com/normal\n"
                )

            result = self.processor.process(None, tmpdir)

            assert result['stats']['graphql_endpoints'] == 4

            # Check graphql_endpoints.txt
            graphql_file = os.path.join(tmpdir, 'graphql_endpoints.txt')
            assert os.path.exists(graphql_file)

    def test_process_with_httpx_json_output(self):
        """Process correctly handles httpx JSON output format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            httpx_dir = os.path.join(tmpdir, 'httpx')
            os.makedirs(httpx_dir)
            with open(os.path.join(httpx_dir, 'httpx_output.txt'), 'w') as f:
                f.write(
                    json.dumps({"url": "https://sub.example.com", "status_code": 200}) + "\n"
                )
                f.write(
                    json.dumps({"url": "https://api.example.com", "status_code": 403}) + "\n"
                )

            result = self.processor.process(None, tmpdir)
            assert result['stats']['total_urls'] == 2

    def test_process_with_empty_dirs(self):
        """Process handles empty or missing tool output directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.processor.process(None, tmpdir)

            assert result['stats']['total_subdomains'] == 0
            assert result['stats']['total_urls'] == 0
            assert result['stats']['param_urls'] == 0
            assert result['stats']['interesting_urls'] == 0
            assert result['stats']['graphql_endpoints'] == 0

            # Output files should still be created (empty)
            assert os.path.exists(os.path.join(tmpdir, 'subdomains.txt'))
            assert os.path.exists(os.path.join(tmpdir, 'all_urls.txt'))

    def test_process_returns_output_files(self):
        """Process returns list of all output file paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = self.processor.process(None, tmpdir)
            assert 'output_files' in result
            assert len(result['output_files']) == 5

            expected_names = [
                'subdomains.txt', 'all_urls.txt', 'param_urls.txt',
                'interesting_urls.txt', 'graphql_endpoints.txt'
            ]
            for name in expected_names:
                assert any(name in f for f in result['output_files'])

    # ── helper methods ────────────────────────────────────────────

    def test_has_params(self):
        """_has_params detects URLs with query strings."""
        assert self.processor._has_params('https://example.com/?q=test') is True
        assert self.processor._has_params('https://example.com/page') is False
        assert self.processor._has_params('https://example.com/?id=1&name=foo') is True

    def test_has_interesting_extension(self):
        """_has_interesting_extension detects interesting file extensions."""
        assert self.processor._has_interesting_extension('https://example.com/app.js') is True
        assert self.processor._has_interesting_extension('https://example.com/index.php') is True
        assert self.processor._has_interesting_extension('https://example.com/page.html') is False
        assert self.processor._has_interesting_extension('https://example.com/login.aspx') is True

    def test_is_graphql_endpoint(self):
        """_is_graphql_endpoint detects GraphQL paths."""
        assert self.processor._is_graphql_endpoint('https://example.com/graphql') is True
        assert self.processor._is_graphql_endpoint('https://example.com/api/graphql') is True
        assert self.processor._is_graphql_endpoint('https://example.com/graphiql') is True
        assert self.processor._is_graphql_endpoint('https://example.com/playground') is True
        assert self.processor._is_graphql_endpoint('https://example.com/api/users') is False

    # ── read/write helpers ────────────────────────────────────────

    def test_read_lines(self):
        """_read_lines reads and strips non-empty lines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, 'test.txt')
            with open(filepath, 'w') as f:
                f.write("line1\n\nline2\nline3\n")
            lines = self.processor._read_lines(filepath)
            assert lines == ['line1', 'line2', 'line3']

    def test_read_lines_missing_file(self):
        """_read_lines returns empty list for missing file."""
        lines = self.processor._read_lines('/nonexistent/path.txt')
        assert lines == []

    def test_write_lines(self):
        """_write_lines writes lines to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, 'output.txt')
            self.processor._write_lines(filepath, ['a', 'b', 'c'])
            with open(filepath, 'r') as f:
                content = f.read()
            assert content == 'a\nb\nc\n'
