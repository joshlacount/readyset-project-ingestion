"""API endpoints."""

import os
import sys
from urllib import parse
import flask
import flask_jwt_extended
import json
import db
import export
import auth
import errors

with open(os.environ.get('SCHEMA_PATH'), 'r') as f:
    schema = json.load(f)

app = flask.Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_KEY')
jwt = flask_jwt_extended.JWTManager(app)

db_address = os.environ.get('DB_ADDRESS')
db_port = os.environ.get('DB_PORT')
db_username = os.environ.get('DB_USERNAME')
db_password = os.environ.get('DB_PASSWORD')
db_auth_source = os.environ.get('DB_AUTH_SOURCE')
db_client = db.DBClient(db_address, db_port, db_username, db_password,
                        db_auth_source)

@app.route('/foo', methods=['GET'])
def foo():
    """Test connection.

    Returns:
      Connection success message.
    """
    return flask.jsonify(message='Connection to API Seccessful'), 200

@app.route('/login', methods=['POST'])
def login():
    """
    Login to the API.

    Returns:
      Access token if authentication successful.  Otherwise, error message.
    """
    username = flask.request.json.get('username', None)
    password = flask.request.json.get('password', None)

    if None in [username, password]:
        return flask.jsonify(error='Missing username and/or password'), 400

    result = None
    def run():
        nonlocal result
        result = db_client.users_get(
            {'username': username},
            include_password=True
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500

    invalid = False
    def run():
        nonlocal invalid
        invalid = (not result or not password or
                   not auth.verify_password(password, result[0]['password']))
    if err := errors.run_hash(run):
        return flask.jsonify(error=err), 500
    if invalid:
        return flask.jsonify(error='Invalid username or password'), 401
    access_token = flask_jwt_extended.create_access_token(identity=username)
    return flask.jsonify(access_token=access_token), 200

@app.route('/testjwt', methods=['GET'])
@flask_jwt_extended.jwt_required()
def test_jwt():
    """Test authentication.

    Returns:
      Success message.
    """
    return flask.jsonify(message='success'), 200

@app.route('/projects/<name>', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_project(name):
    """Get project from database.

    Returns:
      Project or error message.
    """
    result = None
    def run():
        nonlocal result
        result = db_client.projects_get({'name': name})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    
    if len(result) > 0:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Project not found'), 404

@app.route('/projects', methods=['GET'])
@flask_jwt_extended.jwt_required()
def list_projects():
    """Get all projects from database.

    Returns:
      Array of projects or error message.
    """
    result = None
    def run():
        nonlocal result
        result = db_client.projects_get()
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    return flask.jsonify(result), 200

@app.route('/projects/<name>/csv', methods=['GET'])
@flask_jwt_extended.jwt_required()
def export_project_csv(name):
    """Exports a project to CSV.

    Args:
      name: Project name.

    Returns:
      CSV or error message.
    """
    csv = ""
    def run():
        nonlocal csv
        projects = db_client.projects_get({'name': name})
        if projects:
            csv = export.export_project(projects[0], db_client)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not csv:
        return flask.jsonify(error='Project not found'), 404
    return flask.Response(
        csv,
        mimetype='text/csv',
        headers={
            'Content-disposition': f'attachment; filename=project_{name}.csv'
        }
    )

@app.route('/projects', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_project():
    """Add project to database.

    Returns:
      Status message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['projects']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(
            db_client.projects,
            {'name': json['name']}
        )
        if not exists:
            db_client.projects_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if exists:
        return flask.jsonify(error='Project already exists'), 400
    location = '/projects/'+parse.quote(json['name'])
    response_json = {
        'message': 'Project added',
        'url': location
    }
    response = flask.make_response(flask.jsonify(response_json), 201)
    response.headers['Location'] = location
    return response

@app.route('/projects/<name>', methods = ['PATCH'])
@flask_jwt_extended.jwt_required()
def edit_project(name):
    """Edit project in database.

    Args:
      name: Project name.

    Returns:
      Status message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_project']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.projects, {'name': name})
        if exists:
            db_client.projects_update(
                {'name': name},
                {'$set': json}
            )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if exists:
        return flask.jsonify(message='Project updated'), 200
    return flask.jsonify(error='Project not found'), 404

@app.route('/projects/<name>', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_project(name):
    """Delete project from database.

    Args:
      name: Project name.

    Returns:
      Status message.
    """
    exists = False
    def run():
        nonlocal exists 
        exists = db_client.doc_exists(db_client.projects, {'name': name})
        db_client.projects_delete({'name': name})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503 
    if exists:
        return flask.jsonify(message='Delete Sucessful'), 200 
    return flask.jsonify(message='Project not found'), 404

@app.route('/products/<upc>', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_product(upc):
    """Get product from database.

    Args:
      upc: Product upc.

    Returns:
      Product or error message.
    """
    products = None
    def run():
        nonlocal products
        products = db_client.products_get({'upc': upc})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503

    if products:
        return flask.jsonify(products[0]), 200
    return flask.jsonify(error='Product not found'), 404

@app.route('/products', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_product():
    """Add product to database.

    Returns:
      Status message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['products']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.products, {'upc': json['upc']})
        if not exists:
            db_client.products_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if exists:
        return flask.jsonify(error='Product already exists'), 400
    location = '/products/'+parse.quote(json['upc'])
    response_json = {
        'message': 'Product added',
        'url': location
    }
    response = flask.make_response(flask.jsonify(response_json), 201)
    response.headers['Location'] = location
    return response

@app.route('/products/<upc>', methods = ['PATCH'])
@flask_jwt_extended.jwt_required()
def edit_product(upc):
    """Edit product in database.

    Args:
      upc: Product upc.

    Returns:
      Status message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_product']):
        return flask.jsonify(error=err), 400
 
    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.products, {'upc': upc})
        if exists:
            db_client.products_update(
                {'upc': upc},
                {'$set': json}
            )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not exists:
        return flask.jsonify(error='Product not found'), 404
    return flask.jsonify(message='Product updated'), 200

@app.route('/products/<upc>', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_product(upc):
    """Delete product from project.

    Args:
      upc: Product upc.

    Returns:
      Success or error message.
    """
    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.products, {'upc': upc})
        if exists:
            db_client.products_delete({'upc': upc})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if exists:
        return flask.jsonify(message='Product deleted'), 200
    return flask.jsonify(error='Product not found'), 404

@app.route('/templates/<name>', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_template(name):
    """Get template from database.

    Args:
      name: Template name.

    Returns:
      Template or error message.
    """
    templates = []
    def run():
        nonlocal templates
        templates = db_client.templates_get({'name': name})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if templates:
        return flask.jsonify(templates[0]), 200
    return flask.jsonify(error='Template not found'), 404

@app.route('/templates', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_template():
    """Add template to database.

    Args:
      name: Template name.

    Returns:
      Status message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['templates']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(
            db_client.templates,
            {'name': json['name']}
        )
        if not exists:
            db_client.templates_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if exists:
        return flask.jsonify(error='Template already exists'), 400
    location = '/templates/'+parse.quote(json['name'])
    response_json = {
        'message': 'Template added',
        'url': location
    }
    response = flask.make_response(flask.jsonify(response_json), 201)
    response.headers['Location'] = location
    return response
    
@app.route('/templates/<name>', methods = ['PATCH'])
@flask_jwt_extended.jwt_required()
def edit_template(name):
    """Edit template in database.

    Args:
      name: Template name.

    Returns:
      Status message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_template']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.templates, {'name': name})
        if exists:
            db_client.templates_update(
                {'name': name},
                {'$set': json}
            )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not exists:
        return flask.jsonify(error='Template not found'), 404
    return flask.jsonify(message='Template updated'), 200

@app.route('/templates/<name>', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_template(name):
    """Delete template from database.

    Args:
      name: Template name.

    Returns:
      Success or error message.
    """
    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.templates, {'name': name})
        if exists:
            db_client.templates_delete({'name': name})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not exists:
        return flask.jsonify(error='Template not found'), 404
    return flask.jsonify(message='Template deleted'), 200

@app.route('/categories/<name>', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_category(name):
    """Get category from database.

    Returns:
      Category or error message.
    """
    result = None
    def run():
        nonlocal result
        result = db_client.categories_get({'name': name})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not result:
        return flask.jsonify(error='Category not found'), 404
    return flask.jsonify(result[0]), 200

@app.route('/categories', methods=['GET'])
@flask_jwt_extended.jwt_required()
def list_categories():
    """Get all categories from database.

    Returns:
      Array of categories or error message.
    """
    result = None
    def run():
        nonlocal result
        result = db_client.categories_get()
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    return flask.jsonify(result), 200

@app.route('/categories/<name>/csv', methods=['GET'])
@flask_jwt_extended.jwt_required()
def export_category_csv(name):
    """Exports a category to CSV.

    Args:
      name: Category name

    Returns:
      CSV or error message.
    """
    csv = ""
    def run():
        nonlocal csv
        categories = db_client.categories_get({'name': name})
        if categories:
            csv = export.export_category(categories[0], db_client)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not csv:
        return flask.jsonify(error='Category not found'), 404
    return flask.Response(
        csv,
        mimetype='text/csv',
        headers={
            'Content-disposition': f'attachment; filename=category_{name}.csv'
        }
    )

@app.route('/categories', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_category():
    """Add category to database.

    Returns:
      Added category or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['categories']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(
            db_client.categories,
            {'name': json['name']}
        )
        if not exists:
            db_client.categories_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    location = '/categories/'+parse.quote(json['name'])
    response_json = {
        'message': 'Category added',
        'url': location
    }
    response = flask.make_response(flask.jsonify(response_json), 201)
    response.headers['Location'] = location
    return response
 
@app.route('/categories/<name>', methods = ['PATCH'])
@flask_jwt_extended.jwt_required()
def edit_category(name):
    """Edit category in database.

    Args:
      name: Category name.

    Returns:
      Edited category or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_category']):
        return flask.jsonify(error=err), 400

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.categories, {'name': name})
        if exists:
            db_client.categories_update({'name': name}, {'$set': json})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not exists:
        return flask.jsonify(error='Category not found'), 404
    return flask.jsonify(message='Category updated'), 200

@app.route('/categories/<name>', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_category(name):
    """Delete category from database.

    Args:
      name: Category name.

    Returns:
      Success or error message.
    """
    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.categories, {'name': name})
        if exists:
            db_client.categories_delete({'name': name})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not exists:
        return flask.jsonify(error='Category not found'), 404
    return flask.jsonify(data='Category deleted'), 200

@app.route('/users/<username>', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_user(username):
    """Get user from database.

    Args:
      username

    Returns:
      User or error message.
    """
    result = None
    def run():
        nonlocal result
        result = db_client.users_get({'username': username})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    if not result:
        return flask.jsonify(error='User not found'), 404
    return flask.jsonify(result[0]), 200

@app.route('/users', methods=['GET'])
@flask_jwt_extended.jwt_required()
def list_users():
    """Get all users from database.

    Returns:
      Array of users or error message.
    """
    result = None
    def run():
        nonlocal result
        result = db_client.users_get()
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 503
    return flask.jsonify(result), 200

@app.route('/users', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_user():
    """Add user to database.

    Returns:
      Added user or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['users']):
        return flask.jsonify(error=err), 400

    exists = False
    def run_hash():
        nonlocal json
        json['password'] = auth.hash_password(json['password'])
    def run_db():
        nonlocal exists
        exists = db_client.doc_exists(
            db_client.users,
            {'username': json['username']}
        )
        if not exists:
            db_client.users_add(json)
    if (err := errors.run_hash(run_hash)) or (err := errors.run_db_ops(run_db)):
        return flask.jsonify(error=err), 503
    if exists:
        return flask.jsonify(error='User already exists'), 400
    location = '/users/'+parse.quote(json['username'])
    response_json = {
        'message': 'User added',
        'url': location
    }
    response = flask.make_response(flask.jsonify(response_json), 201)
    response.headers['Location'] = location
    return response

@app.route('/users/<username>', methods = ['PATCH'])
@flask_jwt_extended.jwt_required()
def edit_user(username):
    """Edit user in database.

    Args:
      username

    Returns:
      Edited user or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_user']):
        return flask.jsonify(error=err), 400

    exists = False
    def run_hash():
        nonlocal json
        if 'password' in json:
            json['password'] = auth.hash_password(
                json['password']
            )
    def run_db():
        nonlocal exists
        exists = db_client.doc_exists(db_client.users, {'username': username})
        if exists:
            db_client.users_update({'username': username},{'$set': json})
    if (err := errors.run_hash(run_hash)) or (err := errors.run_db_ops(run_db)):
        return flask.jsonify(error=err), 503
    if not exists:
        return flask.jsonify(error='User not found'), 404
    return flask.jsonify(message='User updated'), 200

@app.route('/users/<username>', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_user(username):
    """Delete user from database.

    Args:
      username

    Returns:
      Success or error message.
    """
    if username == 'admin':
        return flask.jsonify(error="Can't delete user admin"), 405

    exists = False
    def run():
        nonlocal exists
        exists = db_client.doc_exists(db_client.users, {'username': username})
        result = db_client.users_delete({'username': username})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if exists:
        return flask.jsonify(data='Delete Sucessful'), 200
    return flask.jsonify(error='User not found'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0')
