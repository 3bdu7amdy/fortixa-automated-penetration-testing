"""Base tool runner - abstract base class for all security tool plugins."""
import subprocess
import os
import logging

logger = logging.getLogger(__name__)


class BaseToolRunner:
    """Base class for all security tool runners.

    Every tool plugin MUST inherit from this class and implement:
    - build_command(): Build the shell command to execute
    - parse_output(): Parse the tool's raw output into findings
    """

    tool_name: str = None
    default_timeout: int = 600
    default_retries: int = 2

    def build_command(self, target: str, options: dict) -> list:
        """Build the command arguments list.

        Args:
            target: The target to scan (domain, IP, URL)
            options: Tool-specific options

        Returns:
            List of command arguments (for subprocess.run)

        IMPORTANT: Must validate all inputs to prevent command injection.
        NEVER use shell=True.
        """
        raise NotImplementedError("Subclasses must implement build_command()")

    def parse_output(self, stdout: str, stderr: str, output_dir: str) -> dict:
        """Parse the tool's raw output.

        Args:
            stdout: Standard output from the tool
            stderr: Standard error from the tool
            output_dir: Directory to save parsed output files

        Returns:
            Dictionary with:
            - 'findings': list of finding dictionaries
            - 'output_files': list of output file paths
            - 'stats': dictionary of statistics
        """
        raise NotImplementedError("Subclasses must implement parse_output()")

    def validate_target(self, target: str) -> bool:
        """Validate that the target string is safe to use in a command.

        MUST be called in build_command() before using the target.
        Prevents command injection attacks.
        """
        dangerous_chars = [';', '&', '|', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']
        for char in dangerous_chars:
            if char in target:
                logger.warning(f"Dangerous character '{char}' found in target: {target}")
                return False
        return True

    def _inject_cookie(self, command: list, cookie: str) -> list:
        """Inject an authentication cookie into a tool command.

        Each tool has its own flag for cookies. This method detects which
        tool is being run and adds the appropriate flag.

        Args:
            command: The original command list (e.g. ['sqlmap', '-u', 'http://...']).
            cookie: The cookie string (e.g. 'PHPSESSID=abc123; security=low').

        Returns:
            The modified command list with cookie flags added.
        """
        if not command or not cookie:
            return command

        binary = command[0]
        # Sanitize cookie - remove any dangerous characters
        safe_cookie = cookie.replace(';', '; ').strip()
        # Remove any shell metacharacters that could cause injection
        for char in ['`', '$', '|', '&', ';', '\n', '\r']:
            safe_cookie = safe_cookie.replace(char, '')

        if binary == 'sqlmap':
            # sqlmap uses --cookie
            return command + ['--cookie', safe_cookie]
        elif binary == 'dalfox':
            # dalfox uses --cookie
            return command + ['--cookie', safe_cookie]
        elif binary == 'commix':
            # commix uses --cookie
            return command + ['--cookie', safe_cookie]
        elif binary == 'nuclei':
            # nuclei uses -H for headers
            return command + ['-H', f'Cookie: {safe_cookie}']
        elif binary == 'httpx':
            # httpx uses -H for headers
            return command + ['-H', f'Cookie: {safe_cookie}']
        elif binary == 'tplmap':
            # tplmap uses --cookie
            return command + ['--cookie', safe_cookie]
        elif binary == 'dotdotpwn':
            # dotdotpwn doesn't support cookies directly, skip
            return command
        else:
            # Default: try -H header (works for HTTP-based tools)
            return command + ['-H', f'Cookie: {safe_cookie}']

    def run(self, target: str, options: dict, output_dir: str) -> dict:
        """Execute the tool and parse results.

        This method should NOT be overridden. It handles:
        - Command execution
        - Timeout management
        - Output capture
        - Error handling
        - Auth cookie injection (for tools that support it)
        """
        os.makedirs(output_dir, exist_ok=True)

        # Ensure output_dir is available to build_command via options
        if 'output_dir' not in options:
            options['output_dir'] = output_dir

        command = self.build_command(target, options)

        # Inject auth cookie for tools that support it
        auth_cookie = options.get('auth_cookie')
        if auth_cookie:
            command = self._inject_cookie(command, auth_cookie)

        logger.info(f"[{self.tool_name}] Running command: {' '.join(command)}")

        timeout = options.get('timeout', self.default_timeout)

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Save raw output (truncated to 1MB to prevent disk fill)
            MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB
            stdout_path = os.path.join(output_dir, f'{self.tool_name}_stdout.txt')
            stderr_path = os.path.join(output_dir, f'{self.tool_name}_stderr.txt')

            stdout_data = result.stdout or ''
            stderr_data = result.stderr or ''

            # Truncate if too large
            if len(stdout_data) > MAX_OUTPUT_SIZE:
                stdout_data = stdout_data[:MAX_OUTPUT_SIZE] + '\n... [truncated]'
            if len(stderr_data) > MAX_OUTPUT_SIZE:
                stderr_data = stderr_data[:MAX_OUTPUT_SIZE] + '\n... [truncated]'

            with open(stdout_path, 'w') as f:
                f.write(stdout_data)
            with open(stderr_path, 'w') as f:
                f.write(stderr_data)

            # Parse output
            parsed = self.parse_output(stdout_data, stderr_data, output_dir)
            parsed['exit_code'] = result.returncode
            parsed['stdout_path'] = stdout_path
            parsed['stderr_path'] = stderr_path

            return parsed

        except subprocess.TimeoutExpired:
            logger.error(f"[{self.tool_name}] Timeout after {timeout}s")
            return {
                'exit_code': -1,
                'error': f'Timeout after {timeout} seconds',
                'findings': [],
                'output_files': [],
                'stats': {}
            }
        except Exception as e:
            logger.error(f"[{self.tool_name}] Unexpected error: {str(e)}")
            return {
                'exit_code': -1,
                'error': str(e),
                'findings': [],
                'output_files': [],
                'stats': {}
            }
