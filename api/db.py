"""Module for performing operations on a MongoDB instance.

Contains the DBClient class for connecting to a MongoDB instance and performing
common low-level operations.
"""

import pymongo
from pymongo import errors as pmerrors
from urllib import parse
import itertools
import errors

# Database and collection names
_DB = 'pi'
_COLLECTIONS = [
    'projects',
    'products',
    'templates',
    'categories',
    'users',
]
_OPERATIONS = [
    'add',
    'get',
    'update',
    'delete',
]

class DBClient:
    """Client for interacting with a MongoDB instance.

    MongoClient created on init, but connection isn't actually established until
    a database operation is performed.  Use check_connection() to confirm
    connection to database.
    """

    def __init__(self, host, port, user, password, auth_source):
        """Initializes client with connection information.

        Args:
          host: Database address.
          port: Port database is running on.
          user: Database username for authentication.
          password: User password for authentication.
          auth_source: Collection to use for authentication.
        """
        uri = ('mongodb://'
               f'{parse.quote_plus(user)}:{parse.quote_plus(password)}'
               f'@{host}:{port}/?authSource={parse.quote_plus(auth_source)}')
        self.client = pymongo.MongoClient(uri)

        self.collections = []
        for col_name in _COLLECTIONS:
            collection = self.client[_DB][col_name]
            setattr(self, col_name, collection)
            self.collections.append(collection)

        def gen_lambda(base_func, collection):
            return lambda *args,**kwargs: base_func(collection, *args, **kwargs)
        for name, collection in zip(_COLLECTIONS, self.collections):
            for op in _OPERATIONS:
                func_name = f'{name}_{op}'
                if hasattr(self, func_name):
                    continue
                base_func = getattr(self, f'_{op}')
                setattr(self, func_name, gen_lambda(base_func, collection))

    def can_connect(self):
        """Checks if connection to the database can be established.

        Returns:
          True for successful connection, False for failed connection.
        """
        try:
            self.client.admin.command('ping')
            return True
        except pmerrors.ServerSelectionError:
            print('Unable to find MongoDB server.  Check address.')
        except pmerrors.PyMongoError as e:
            print(f'Error connecting to MongoDB server - {e.message}')
        return False

    def is_duplicate(self, collection, query, existing=False):
        """Checks if document with id is a duplicate.

        Args:
          col_name: Collection name.
          query: Query to run to find duplicates.
          existing: If True check for duplicates amongst existing documents.
            Else check for would be duplicate.

        Returns:
          True if duplicates detected otherwise False.
        """
        try:
            result = collection.find(query)
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e
        n = len(list(result))
        return n > 1 if existing else n > 0

    def _add(self, collection, doc):
        """Adds new document to a collection.

        Args:
          collection: Reference to collection to add document to.
          doc: Dict of new document.

        Returns:
          The inserted document.
        """
        try:
            result = collection.insert_one(doc)
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e
        return self._get(collection, {'_id': result.inserted_id})[0]

    def _get(self, collection, query=None, projection=None):
        """Gets documents according to query.

        Args:
          query: Query for document selection.
          projection: Projection to apply to results.

        Returns:
          List of documents matching query.
        """
        if query is None:
            query = {}
        if projection is None:
            projection = {'_id': 0}
        try:
            result = collection.find(query, projection)
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e 
        return list(result)

    def _update(self, collection, query, update):
        """Updates documents.

        Args:
          query: Query for document selection.
          update: Update to apply.

        Returns:
          List of updated documents.  None if no documents updated.
        """
        try:
            result = collection.update_many(query, update)    
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e
        return (self._get(collection, query)
                if result.modified_count > 0 else None)

    def _delete(self, collection, query):
        """Deletes documents according to query.

        Args:
          query: Query for document selection.
        
        Returns:
          True if deleted count > 0 otherwise False.
        """
        try:
            return collection.delete_many(query).deleted_count > 0
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e

    def templates_delete(self, query):
        """Deletes templates according to query.

        Custom function to update other documents that reference the deleted
        templates.

        Args:
          query: Query for document selection.
        
        Returns:
          True if deleted count > 0 otherwise False.
        """
        to_be_deleted = [template['name'] for template in
                         self.templates_get(query, {'name': 1})]
        self.categories_update(
            {'templates': {'$all': to_be_deleted}},
            {'$pullAll': {'templates': to_be_deleted}}
        )
        self.products_update(
            {'template_name': {'$in': to_be_deleted}},
            {'$set': {'template_name': ''}}
        )
        return self._delete(self.templates, query)

    def categories_delete(self, query):
        """Deletes categories according to query.

        Custom function to move templates in deleted category to the
        Default category.

        Args:
          query: Query for document selection.
        
        Returns:
          True if deleted count > 0 otherwise False.
        """
        templates = list(itertools.chain(
            *[category['templates'] for category in
              self.categories_get(query)]
        ))
        self.categories_update(
            {'name': 'Default'},
            {'$push': {'templates': {'$each': templates}}}
        )
        return self._delete(self.categories, query)

    def users_add(self, user):
        """Add new user.

        Custom function to remove password from returned documents.

        Args:
          user: Dict for new user

        Returns:
          The inserted user document.
        """
        try:
            result = self.users.insert_one(user)
            return self.users.find_one(
                {'_id': result.inserted_id},
                {'_id': 0, 'password': 0}
            )
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e

    def users_get(self, query=None, projection=None, include_password=False):
        """Get users.

        Custom function with explicit option to include password in results.

        Args:
          query: Query for document selection.
          projection: Projection to apply to results.
          include_password: Include password in projection or not.

        Returns:
          List of user documents matching query.
        """
        if query is None:
            query = {}
        if projection is None:
            projection = {'_id': 0}
        if not include_password:
            projection['password'] = 0
        try:
            return list(self.users.find(query, projection))
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e

    def users_update(self, query, update):
        """Update user.

        Custom function to remove password from returned documents.

        Args:
          query: Query for document selection.
          update: Update to apply.

        Returns:
          List of updated documents.  None if no documents updated.
        """
        try:
            result = self.users.update_many(query, update)
            return (self.users.find(query, {'_id': 0, 'password': 0})
                    if result.modified_count > 0 else None)
        except pmerrors.PyMongoError as e:
            raise errors.DatabaseError(e.message) from e
