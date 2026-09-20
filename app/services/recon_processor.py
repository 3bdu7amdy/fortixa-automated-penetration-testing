"""Recon Processor - post-processes recon scan results.

Collects, deduplicates, and categorizes output from multiple
reconnaissance tools into consolidated output files.
"""
import os
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Interesting file extensions to look for in URLs
INTERESTING_EXTENSIONS = {'.js', '.php', '.asp', '.aspx', '.jsp'}

# Known GraphQL endpoint paths
GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/graphiql', '/playground']

# Tools that produce subdomain output
SUBDOMAIN_TOOLS = ['subfinder', 'assetfinder', 'amass']

# Tools that produce URL output
URL_TOOLS = ['httpx', 'waybackurls', 'gau', 'katana']


class ReconProcessor:
    """Post-processes recon scan results.

    After a recon scan completes, this processor:
    1. Collects all subdomains from different tools
    2. Deduplicates subdomains
    3. Writes combined subdomains.txt
    4. Collects all URLs from different tools
    5. Deduplicates URLs
    6. Extracts URLs with parameters (param_urls.txt)
    7. Extracts interesting file extensions
    8. Checks for GraphQL endpoints
    9. Writes processed output files
    """

    def process(self, scan, output_base_dir: str) -> dict:
        """Post-process recon scan results.

        Args:
            scan: Scan model instance with jobs relationship
            output_base_dir: Base directory containing tool output subdirectories

        Returns:
            Dictionary with processing stats and output file paths.
        """
        os.makedirs(output_base_dir, exist_ok=True)

        # 1. Collect all subdomains
        subdomains = self._collect_subdomains(scan, output_base_dir)

        # 2. Deduplicate subdomains
        subdomains = list(dict.fromkeys(subdomains))  # preserves order
        subdomains = sorted(set(s.lower() for s in subdomains))

        # 3. Write combined subdomains.txt
        subdomains_file = os.path.join(output_base_dir, 'subdomains.txt')
        self._write_lines(subdomains_file, subdomains)

        # 4. Collect all URLs
        urls = self._collect_urls(scan, output_base_dir)

        # 5. Deduplicate URLs
        urls = list(dict.fromkeys(urls))  # preserves order
        urls = sorted(set(u.strip() for u in urls if u.strip()))

        # 6. Extract URLs with parameters
        param_urls = [u for u in urls if self._has_params(u)]
        param_urls_file = os.path.join(output_base_dir, 'param_urls.txt')
        self._write_lines(param_urls_file, param_urls)

        # 7. Extract interesting file extensions
        interesting_urls = [u for u in urls if self._has_interesting_extension(u)]
        interesting_file = os.path.join(output_base_dir, 'interesting_urls.txt')
        self._write_lines(interesting_file, interesting_urls)

        # 8. Check for GraphQL endpoints
        graphql_urls = [u for u in urls if self._is_graphql_endpoint(u)]
        graphql_file = os.path.join(output_base_dir, 'graphql_endpoints.txt')
        self._write_lines(graphql_file, graphql_urls)

        # 9. Write all URLs
        all_urls_file = os.path.join(output_base_dir, 'all_urls.txt')
        self._write_lines(all_urls_file, urls)

        stats = {
            'total_subdomains': len(subdomains),
            'total_urls': len(urls),
            'param_urls': len(param_urls),
            'interesting_urls': len(interesting_urls),
            'graphql_endpoints': len(graphql_urls),
        }

        output_files = [
            subdomains_file,
            all_urls_file,
            param_urls_file,
            interesting_file,
            graphql_file,
        ]

        logger.info(
            f"Recon processing complete: {len(subdomains)} subdomains, "
            f"{len(urls)} URLs, {len(param_urls)} with params, "
            f"{len(graphql_urls)} GraphQL endpoints"
        )

        return {
            'stats': stats,
            'output_files': output_files,
        }

    def _collect_subdomains(self, scan, output_base_dir: str) -> list:
        """Collect subdomains from all subdomain-producing tool outputs.

        Args:
            scan: Scan model instance
            output_base_dir: Base output directory

        Returns:
            List of raw subdomain strings.
        """
        subdomains = []

        for tool_name in SUBDOMAIN_TOOLS:
            tool_dir = os.path.join(output_base_dir, tool_name)
            if not os.path.isdir(tool_dir):
                continue

            # Try the standard output file naming pattern
            output_file = os.path.join(tool_dir, f'{tool_name}_output.txt')
            if os.path.exists(output_file):
                subdomains.extend(self._read_lines(output_file))
                continue

            # Try stdout file from base runner
            stdout_file = os.path.join(tool_dir, f'{tool_name}_stdout.txt')
            if os.path.exists(stdout_file):
                subdomains.extend(self._read_lines(stdout_file))

        return subdomains

    def _collect_urls(self, scan, output_base_dir: str) -> list:
        """Collect URLs from all URL-producing tool outputs.

        Args:
            scan: Scan model instance
            output_base_dir: Base output directory

        Returns:
            List of raw URL strings.
        """
        urls = []

        for tool_name in URL_TOOLS:
            tool_dir = os.path.join(output_base_dir, tool_name)
            if not os.path.isdir(tool_dir):
                continue

            # Try the standard output file naming pattern
            output_file = os.path.join(tool_dir, f'{tool_name}_output.txt')
            if os.path.exists(output_file):
                urls.extend(self._extract_urls_from_file(output_file, tool_name))
                continue

            # Try stdout file from base runner
            stdout_file = os.path.join(tool_dir, f'{tool_name}_stdout.txt')
            if os.path.exists(stdout_file):
                urls.extend(self._extract_urls_from_file(stdout_file, tool_name))

        return urls

    def _extract_urls_from_file(self, filepath: str, tool_name: str) -> list:
        """Extract URLs from a tool output file.

        Some tools output JSON (httpx), others output plain text.

        Args:
            filepath: Path to the output file
            tool_name: Name of the tool that produced the output

        Returns:
            List of URL strings.
        """
        import json

        urls = []
        lines = self._read_lines(filepath)

        for line in lines:
            if not line.strip():
                continue

            # Try JSON parsing (httpx)
            if tool_name == 'httpx':
                try:
                    data = json.loads(line)
                    url = data.get('url', data.get('input', ''))
                    if url:
                        urls.append(url)
                        continue
                except json.JSONDecodeError:
                    pass

            # Plain text URL
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)

        return urls

    @staticmethod
    def _has_params(url: str) -> bool:
        """Check if a URL has query parameters.

        Args:
            url: URL string to check

        Returns:
            True if the URL contains query parameters.
        """
        parsed = urlparse(url)
        return bool(parsed.query)

    @staticmethod
    def _has_interesting_extension(url: str) -> bool:
        """Check if a URL has an interesting file extension.

        Args:
            url: URL string to check

        Returns:
            True if the URL path ends with an interesting extension.
        """
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        for ext in INTERESTING_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False

    @staticmethod
    def _is_graphql_endpoint(url: str) -> bool:
        """Check if a URL points to a GraphQL endpoint.

        Args:
            url: URL string to check

        Returns:
            True if the URL path matches a known GraphQL endpoint pattern.
        """
        parsed = urlparse(url)
        path_lower = parsed.path.lower().rstrip('/')
        for graphql_path in GRAPHQL_PATHS:
            if path_lower == graphql_path or path_lower.endswith(graphql_path):
                return True
        return False

    @staticmethod
    def _read_lines(filepath: str) -> list:
        """Read all non-empty lines from a file.

        Args:
            filepath: Path to the file

        Returns:
            List of stripped, non-empty lines.
        """
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except (IOError, OSError):
            return []

    @staticmethod
    def _write_lines(filepath: str, lines: list):
        """Write lines to a file.

        Args:
            filepath: Path to the file
            lines: List of strings to write (one per line)
        """
        try:
            with open(filepath, 'w') as f:
                for line in lines:
                    f.write(line + '\n')
        except (IOError, OSError) as e:
            logger.error(f"Failed to write {filepath}: {e}")
