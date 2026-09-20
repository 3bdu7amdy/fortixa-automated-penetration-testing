"""Base Provider - abstract interface for all AI providers."""


class BaseProvider:
    """Base class for all AI providers.

    Each provider must implement the generate_content() method.
    """

    def __init__(self, api_key, model):
        """Initialize the provider.

        Args:
            api_key: The API key string.
            model: The model name to use.
        """
        self.api_key = api_key
        self.model = model

    def generate_content(self, prompt):
        """Generate content from a prompt.

        Args:
            prompt: The input prompt string.

        Returns:
            The generated text string.

        Raises:
            NotImplementedError if the subclass doesn't implement this.
            Exception on API errors.
        """
        raise NotImplementedError("Subclasses must implement generate_content()")
