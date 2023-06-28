import jsonschema

"""Module for custom exceptions.

Contains the DatabaseError class.
"""

class DatabaseError(Exception):
    """Exception for when an error occurs during a database operation."""

    def __init__(self):
        """Initializes superclass."""
        super().__init__()

class HashError(Exception):
    """Exception for when an error occurs during hashing."""

    def __init__(self):
        """Initializes superclass."""
        super().__init__()


def validate_json(json, schema):
    try:
        jsonschema.Draft202012Validator(schema).validate(json)
    except jsonschema.exceptions.ValidationError as err:
        return err.message

def run_db_ops(run):
    try:
        run()
    except DatabaseError as err:
        print(f'Database error!\n{str(err)}')
        return 'Database error'

def run_hash(run):
    try:
        run()
    except HashError as err:
        print(f'Hashing error!\n{str(err)}')
        return 'Hashing error'
