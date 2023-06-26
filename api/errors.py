"""Module for custom exceptions.

Contains the DatabaseError class.
"""

class DatabaseError(Exception):
    """Exception for when an error occurs during a database operation.
    """

    def __init__(self, msg):
        """Initializes with error message.

        Args:
          msg: Error message.
        """
        super().__init__(msg)
