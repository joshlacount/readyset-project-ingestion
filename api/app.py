"""API endpoints."""

import os
import sys
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

@app.route('/projects/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_project():
    """Get project from database.

    Returns:
      Project or error message.
    """

    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['get_project']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.projects_get({'name': json['name']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    
    if len(result) > 0:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Project not found'), 404

@app.route('/projects/all', methods=['GET'])
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
        return flask.jsonify(error=err), 500
    return flask.jsonify(result), 200

@app.route('/projects/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_project():
    """Add project to database.

    Returns:
      Added project or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['projects']):
        return flask.jsonify(error=err), 400

    dup = None
    def run():
        nonlocal dup
        dup = db_client.is_duplicate(
            db_client.projects,
            {'name': json['name']}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if dup:
        return flask.jsonify(error='Project already exists'), 409

    project = None
    def run():
        nonlocal project
        project = db_client.projects_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    return flask.jsonify(project), 200

@app.route('/projects/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_project():
    """Edit project in database.

    Returns:
      Edited project or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_project']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.projects_update(
            {'name': json['name']},
            {'$set': {'products': json['products']}}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    result = result[0] if result is not None else result
    return flask.jsonify(result)

@app.route('/projects/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_project():
    """Delete project from database.

    Returns:
      Success or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['delete_project']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.projects_delete({'name': json['name']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500    
    if result:
        return flask.jsonify(message='Delete Sucessful'), 200 
    return flask.jsonify(message='Project not found'), 404

@app.route('/products/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_product():
    """Get product from database.

    Returns:
      Product or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['get_product']):
        return flask.jsonify(error=err), 400

    products = None
    def run():
        nonlocal products
        products = db_client.products_get({'upc': json['upc']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500

    if len(products) > 0:
        return flask.jsonify(products[0]), 200
    return flask.jsonify(error='Product not found'), 404

@app.route('/products/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_product():
    """Add product to project and database.

    Returns:
      Added product or error message.
    """
    json = flask.request.get_json()
    if ((err := errors.validate_json(json, schema['endpoints']['add_product']))
        or (err := errors.validate_json(json['product'],
                                 schema['collections']['products']))):
        return flask.jsonify(error=err), 400

    product = None
    def run():
        nonlocal product
        if db_client.projects_get({'name': json['project_name']}):
            db_client.projects_update(
                {'name': json['project_name']},
                {'$push': {'products': json['product']['upc']}}
            )
            product = db_client.products_add(json['product'])
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if product:
        return flask.jsonify(product), 200
    return flask.jsonify(error='Project not found'), 404

@app.route('/products/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_product():
    """Edit product in database.

    Returns:
      Edited product or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_product']):
        return flask.jsonify(error=err), 400
 
    result = None
    def run():
        nonlocal result
        result = db_client.products_get({'upc': json['upc']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if not result:
        return flask.jsonify(error=f'Product not found'), 404
    product = result[0]

    def run():
        nonlocal result
        result = db_client.products_update(
            {'upc': json['upc']},
            {'$set': json['updates']}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    result = result[0] if result else product
    return flask.jsonify(result), 200

@app.route('/products/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_product():
    """Delete product from project.

    Returns:
      Success or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['delete_product']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.projects_update(
            {'name': json['project_name']},
            {'$pullAll': {'products': [json['upc']]}}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if not result:
        return flask.jsonify(error='Product not found in project'), 404

    def run():
        nonlocal result
        result = db_client.products_delete({'upc': json['upc']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(message='Product deleted'), 200
    return flask.jsonify(error='Product not found'), 404

@app.route('/templates/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_template():
    """Get template from database.

    Returns:
      Template or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['get_template']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.templates_get({'name': json['name']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Template not found'), 404

@app.route('/templates/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_template():
    """Add template to database.

    Returns:
      Added template or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['templates']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.templates_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    return flask.jsonify(result), 200

@app.route('/templates/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_template():
    """Edit template in database.

    Returns:
      Edited template or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_template']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.templates_update(
            {'name': json['name']},
            {'$set': json['updates']}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Template not found'), 404

@app.route('/templates/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_template():
    """Delete template from database.

    Returns:
      Success or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['delete_template']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.templates_delete({'name': json['name']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(message='Delete Sucessful'), 200
    return flask.jsonify(error='Template not found'), 404

@app.route('/export', methods = ['GET'])
@flask_jwt_extended.jwt_required()
def export_csv():
    """Export document to csv.

    Returns:
      CSV or error message.
    """

    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['export_csv']):
        return flask.jsonify(error=err), 400

    doc_id = json['id']
    doc_id_field = json['id_field']
    collection = json['collection']

    if collection == 'project':
        get_doc_func = getattr(db_client, 'projects_get')
    elif collection == 'category':
        get_doc_func = getattr(db_client, 'categories_get')
    else:
        return flask.jsonify(error=f'{collection} export unavailable'), 400

    export_func = getattr(export, f'export_{collection}')

    result = get_doc_func({doc_id_field: doc_id})
    if not result:
        return flask.jsonify(error='Document not found'), 404

    csv_str = None
    def run():
        nonlocal csv_str
        csv_str = export_func(result[0], db_client)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    return flask.Response(
        csv_str,
        mimetype='text/csv',
        headers={
            'Content-disposition': ('attachment; filename='
                                    f'{collection}_{doc_id}.csv')
        }
    )

@app.route('/categories/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_category():
    """Get category from database.

    Returns:
      Category or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['get_category']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.categories_get({'name': json['name']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Category not found'), 404

@app.route('/categories/all', methods=['GET'])
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
        return flask.jsonify(error=err), 500
    return flask.jsonify(result), 200

@app.route('/categories/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_category():
    """Add category to database.

    Returns:
      Added category or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['categories']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.categories_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    return flask.jsonify(result), 200

@app.route('/categories/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_category():
    """Edit category in database.

    Returns:
      Edited category or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_category']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.categories_update(
            {'name': json['name']},
            {'$set': json['updates']}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Category not found'), 404

@app.route('/categories/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_category():
    """Delete category from database.

    Returns:
      Success or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['delete_category']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.categories_delete({'name': json['name']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(data='Delete Sucessful'), 200
    return flask.jsonify(error='Category not found'), 404

@app.route('/users/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_user():
    """Get user from database.

    Returns:
      User or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['get_user']):
        return flask.jsonify(error=err), 400

    result = None
    def run():
        nonlocal result
        result = db_client.users_get({'username': json['username']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error=f'User not found'), 404

@app.route('/users/all', methods=['GET'])
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
        return flask.jsonify(error=err), 500
    return flask.jsonify(result), 200

@app.route('/users/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_user():
    """Add user to database.

    Returns:
      Added user or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['collections']['users']):
        return flask.jsonify(error=err), 400

    def run():
        nonlocal json
        json['password'] = auth.hash_password(json['password'])
    if err := errors.run_hash(run):
        return flask.jsonify(error=err), 500

    result = None
    def run():
        nonlocal result
        result = db_client.users_add(json)
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    return flask.jsonify(result), 200

@app.route('/users/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_user():
    """Edit user in database.

    Returns:
      Edited user or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['edit_user']):
        return flask.jsonify(error=err), 400

    if 'password' in json['updates']:
        def run():
            nonlocal json
            json['updates']['password'] = auth.hash_password(
                json['updates']['password']
            )
        if err := errors.run_hash(run):
            return flask.jsonify(error=err), 500
    result = None
    def run():
        nonlocal result
        result = db_client.users_update(
            {'username': json['username']},
            {'$set': json['updates']}
        )
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='User not found'), 404

@app.route('/users/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_user():
    """Delete user from database.

    Returns:
      Success or error message.
    """
    json = flask.request.get_json()
    if err := errors.validate_json(json, schema['endpoints']['delete_user']):
        return flask.jsonify(error=err), 400

    if json['username'] == 'admin':
        return flask.jsonify(message="Can't delete user admin."), 405

    result = None
    def run():
        nonlocal result
        result = db_client.users_delete({'username': json['username']})
    if err := errors.run_db_ops(run):
        return flask.jsonify(error=err), 500
    if result:
        return flask.jsonify(data='Delete Sucessful'), 200
    return flask.jsonify(error='User not found'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0')
