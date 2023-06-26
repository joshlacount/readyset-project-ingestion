"""API endpoints."""

import os
import sys
import flask
import flask_jwt_extended
import json
import jsonschema
from jsonschema import exceptions
import db
import export
import auth
import errors

def validate_json(json, schema):
    try:
        jsonschema.Draft202012Validator(schema).validate(json)
    except exceptions.ValidationError as err:
        return err.message


# Init the Dependencies and API, the code is kinda messy up here.
#
# The main API codebase starts after login function and is much easier to read.
#
# The DOCString Comments are an idea for what the functions will end up doing
# (some are not fully flushed yet because of ambiguity).
#

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
if not db_client.can_connect():
    print('Unable to connect to database!')
    sys.exit(1)

#Test Route for Environment Variables
@app.route('/debug', methods=['GET'])
@flask_jwt_extended.jwt_required()
def debug():
    serializable_env = {k: v for k, v in os.environ.items()
                        if isinstance(v, str)}
    return flask.jsonify(serializable_env), 200

#Test Environment Variable
@app.route('/envars', methods=['GET'])
@flask_jwt_extended.jwt_required()
def envars():
    return flask.jsonify(message=os.environ.get('TEST_VARIABLE')), 200

#Basic Test API Endpoint to ensure it is up and running
@app.route('/foo', methods=['GET'])
def foo():
    return flask.jsonify(message='Connection to API Seccessful'), 200

# Base Login endpoint
@app.route('/login', methods=['POST'])
def login():
    """
    Login to the API with credential provided in the websites Login Page.

    If Invalid credentials are provided this function will reject the login

    Otherwise it will return a new valid JWT access token inside of a JSON
    object 
    """
    username = flask.request.json.get('username', None)
    password = flask.request.json.get('password', None)

    if None in [username, password]:
        return flask.jsonify(error='Missing username and/or password'), 400

    try:
        result = db_client.users_get(
            {'username': username},
            include_password=True
        )
    except errors.DatabaseError as e:
        print(f'Database error! -- {str(e)}')
        return flask.jsonify(error='Database operation failed'), 500
    if (not result or password is None or
        not auth.verify_password(password, result[0]['password'])):
        return flask.jsonify(error='Invalid username or password'), 401
    access_token = flask_jwt_extended.create_access_token(identity=username)
    return flask.jsonify(access_token=access_token), 200

@app.route('/testjwt', methods=['GET'])
@flask_jwt_extended.jwt_required()
def test_jwt():
    return flask.jsonify('success'), 200

##### Projects API Endpoints #####

@app.route('/projects/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_project():
    """Base Function to Retrieve the Project from the MongoDB database using
    the project name as an ID

    Parameter
    ---------
    project_name : str

    Returns
    ---------
    Project : JSON Object
    """

    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['get_project']):
        return flask.jsonify(error=err), 400

    try:
        result = db_client.projects_get({'name': json['name']})
    except errors.DatabaseError as e:
        print(f'Database error! -- {str(e)}')
        return flask.jsonify(error='Database operation failed'), 500
    if len(result) > 0:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(
        message=f"Project {json['name']} not found."
    ), 400

# Protected API endpoint, List all Projects
@app.route('/projects/all', methods=['GET'])
@flask_jwt_extended.jwt_required()
def list_projects():
    try:
        projects = db_client.projects_get()
    except errors.DatabaseError as e:
        print(f'Database error! -- {str(e)}')
        return flask.jsonify(error='Database operation failed'), 500
    return flask.jsonify(projects), 200

# Create new Project Protected API endpoint
@app.route('/projects/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_project():
    """
    Function to add a blank project to the database.
    Parameter
    ---------
    Takes in a JSON object formatted as a project as a parameter,
    requires a name

    Returns
    ---------
    Project : JSON object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['collections']['projects']):
        return flask.jsonify(error=err), 400

    try:
        dup = db_client.is_duplicate(
            db_client.projects,
            {'name': json['name']}
        )
    except errors.DatabaseError as e:
        print(f'Database error! -- {str(e)}')
        return flask.jsonify(error='Database operation failed'), 500
    if dup:
        return flask.jsonify(
            message=f"Project {json['name']} already exists."
        ), 409
    return flask.jsonify(db_client.projects_add(json)), 200

# Edit existing Project Protected API endpoint
@app.route('/projects/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_project():
    """
    Function to edit an existing project in the database.

    Parameters
    ---------
    project_name : str

    Returns
    ---------
    Project : JSON object
    (Will return None if nothing updated, or project not found by name)
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['edit_project']):
        return flask.jsonify(error=err), 400

    try:
        result = db_client.projects_update(
            {'name': json['name']},
            {'$set': {'products': json['products']}}
        )
    except errors.DatabaseError as e:
        print(f'Database error! -- {str(e)}')
        return flask.jsonify(error='Database operation failed'), 500
    result = result[0] if result is not None else result
    return flask.jsonify(result)

# Delete existing Project Protected API endpoint
@app.route('/projects/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_project():
    """
    Function to delete an existing project in the database.

    Parameters:
    project_name : str
    
    Returns
    ---------
    data : JSON object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['delete_project']):
        return flask.jsonify(error=err), 400

    try:
        if db_client.projects_delete({'name': json['name']}):
            return flask.jsonify(message='Delete Sucessful'), 200
    except errors.DatabaseError as e:
        print(f'Database error! -- {str(e)}')
        return flask.jsonify(error='Database operation failed'), 500
    return flask.jsonify(message='Project not found'), 404

##### Products API Endpoints #####

# Retrieve product Protected API endpoint
@app.route('/products/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_product():
    """Function to Retrieve the product from the MongoDB database using the
    product name as an ID

    Parameter
    ---------
    product_name : str

    Returns
    ---------
    Product : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['get_product']):
        return flask.jsonify(error=err), 400
    
    products = db_client.products_get({'upc': json['upc']})
    if len(products) > 0:
        #Sucessful Product Fetch
        return flask.jsonify(products[0]), 200
    #Failed to Retrieve Data (Doesn't Exist)
    return flask.jsonify(
        error=f"Error Fetching Product {json['upc']}. Status Code: 204"
    ), 204

# Create new Product Protected API endpoint
@app.route('/products/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_product():
    """Function to add a new product linked to a specified project

    Parameter
    ---------
    Takes in a Product JSON through the request
    And project_name (str) through the URL

    Returns
    ---------
    Project : JSON Object
    """
    json = flask.request.get_json()
    if ((err := validate_json(json, schema['endpoints']['add_product']))
        or (err := validate_json(json['product'],
                                 schema['collections']['products']))):
        return flask.jsonify(error=err), 400
    
    if db_client.projects_get({'name': json['project_name']}):
        db_client.projects_update(
            {'name': json['project_name']},
            {'$push': {'products': json['product']['upc']}}
        )
        new_product = db_client.products_add(json['product'])
        return flask.jsonify(new_product), 200
    return flask.jsonify(error='Project not found'), 404

# Edit existing Product Protected API endpoint
@app.route('/products/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_product():
    """Function to edit a product based of the product name

    Parameter
    ---------
    product_name : str
    also takes in a json of updates

    Returns
    ---------
    Product : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['edit_product']):
        return flask.jsonify(error=err), 400
    
    result = db_client.products_get({'upc': json['upc']})
    if not result:
        return flask.jsonify(error=f'Product not found'), 404
    product = result[0]
    result = db_client.products_update(
        {'upc': json['upc']},
        {'$set': json['updates']}
    )
    result = result[0] if result else product
    return flask.jsonify(result), 200

# Delete existing Product Protexted API endpoint
@app.route('/products/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_product():
    """Function to delete a product based of the products UPC

    Parameter
    ---------
    json object with the format:
    {
        "product_upc" : string
        "project_name" : string
    }

    Returns
    ---------
    data : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['delete_product']):
        return flask.jsonify(error=err), 400
    
    result = db_client.projects_update(
        {'name': json['project_name']},
        {'$pullAll': {'products': [json['upc']]}}
    )
    if not result:
        return flask.jsonify(error='Product not found in project'), 404
    if db_client.products_delete({'upc': json['upc']}):
        return flask.jsonify(message='Product deleted'), 200
    return flask.jsonify(error='Product not found'), 404

##### Templates API Endpoints #####

# Retrieve Template Protected API endpoint
@app.route('/templates/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_template():
    """Function to fetch template data based on the unique template name

    Parameter
    ---------
    template_name : str

    Returns
    ---------
    template : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['get_template']):
        return flask.jsonify(error=err), 400
    
    result = db_client.templates_get({'name': json['name']})
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='Template not found'), 404

# Create new Template Protected API endpoint
@app.route('/templates/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_template():
    """Function to add a new blank template based on a template name

    Parameter
    ---------
    Takes in a json of structure template (Structure in the docs page)

    Returns
    ---------
    Template:  JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['collections']['templates']):
        return flask.jsonify(error=err), 400

    return flask.jsonify(db_client.templates_add(json)), 200

# Edit existing Template Protected API endpoint
@app.route('/templates/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_template():
    """Function to edit an existing template using the unique template name
    Parameter
    ---------
    Takes in a json a json template structure

    Returns
    ---------
    template : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['edit_template']):
        return flask.jsonify(error=err), 400

    result = db_client.templates_update(
        {'name': json['name']},
        {'$set': json['updates']}
    )
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(
        message=f'Template with name {template_name} not found'
    ), 404

# Delete existing Template Protected API endpoint
@app.route('/templates/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_template():
    """Function to delete an existing template using the unique template name

    Parameter
    ---------
    template_name : str

    Returns
    ---------
    message : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['delete_template']):
        return flask.jsonify(error=err), 400

    if db_client.templates_delete({'name': json['name']}):
        return flask.jsonify(message='Delete Sucessful'), 200
    return flask.jsonify(error='Template not found'), 404

##### Export API Endpoints #####

# Export document to CSV Protected API endpoint
@app.route('/export', methods = ['GET'])
@flask_jwt_extended.jwt_required()
def export_csv():
    """Function to export a document from a collection based on a unique ID

    Paramter
    --------
    collection : str

    Returns
    --------
    csv : Response
    """

    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['export_csv']):
        return flask.jsonify(error=err), 400

    doc_id = json['id']
    doc_id_field = json['id_field']
    collection = json['collection']

    if collection == 'project':
        get_doc_func = getattr(db_client, 'projects_get')
    elif collection == 'category':
        get_doc_func = getattr(db_client, 'categories_get')
    else:
        return flask.jsonify(message=f'{collection} export unavailable'), 400

    export_func = getattr(export, f'export_{collection}')

    result = get_doc_func({doc_id_field: doc_id})
    if not result:
        return flask.jsonify(error='Document not found'), 404

    csv_str = export_func(result[0], db_client)
    return flask.Response(
        csv_str,
        mimetype='text/csv',
        headers={
            'Content-disposition': ('attachment; filename='
                                    f'{collection}_{doc_id}.csv')
        }
    )

##### Category API Endpoints #####

# Protected API endpoint for, Get Category
@app.route('/categories/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_category():
    """Base Function to Retrieve the Category from the MongoDB database using
    the category name as an ID

    Parameter
    ---------
    category_name : str

    Returns
    ---------
    Category : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['get_category']):
        return flask.jsonify(error=err), 400

    result = db_client.categories_get({'name': json['name']})
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error=f'Category not found'), 404

# Protected API endpoint, List all Categories
@app.route('/categories/all', methods=['GET'])
@flask_jwt_extended.jwt_required()
def list_categories():
    categories = db_client.categories_get()
    return flask.jsonify(categories), 200

# Create new Category Protected API endpoint
@app.route('/categories/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_category():
    """
    Function to add a new category to the database.
    Parameter
    ---------
    Takes in a JSON object formatted as a category as a parameter, requires a
    name

    Returns
    ---------
    Category : JSON object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['collections']['categories']):
        return flask.jsonify(error=err), 400

    return flask.jsonify(db_client.categories_add(json)), 200

# Edit existing Category Protected API endpoint
@app.route('/categories/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_category():
    """
    Function to edit an existing category in the database.

    Parameters
    ---------
    category_name : str

    Returns
    ---------
    Category : JSON object
    (Will return false if nothing updated, or category not found by name)
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['edit_category']):
        return flask.jsonify(error=err), 400

    result = db_client.categories_update(
        {'name': json['name']},
        {'$set': json['updates']}
    )
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error=f'Category not found'), 404

# Delete existing Category Protected API endpoint
@app.route('/categories/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_category():
    """
    Function to delete an existing category in the database.

    Parameters:
    category_name : str
    
    Returns
    ---------
    data : JSON object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['delete_category']):
        return flask.jsonify(error=err), 400

    if db_client.categories_delete({'name': json['name']}):
        return flask.jsonify(data='Delete Sucessful'), 200
    return flask.jsonify(error='Category not found'), 404

##### User API Endpoints #####

# Protected API endpoint for, Get User
@app.route('/users/get', methods=['GET'])
@flask_jwt_extended.jwt_required()
def get_user():
    """Base Function to Retrieve the User from the MongoDB database using the
    username as an ID

    Parameter
    ---------
    username : str

    Returns
    ---------
    User : JSON Object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['get_user']):
        return flask.jsonify(error=err), 400

    result = db_client.users_get({'username': json['username']})
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error=f'User not found'), 404

# Protected API endpoint, List all Users
@app.route('/users/all', methods=['GET'])
@flask_jwt_extended.jwt_required()
def list_users():
    users = db_client.users_get()
    return flask.jsonify(users), 200

# Create new User Protected API endpoint
@app.route('/users/add', methods = ['POST'])
@flask_jwt_extended.jwt_required()
def add_user():
    """
    Function to add a new user to the database.
    Parameter
    ---------
    Takes in a JSON object formatted as a user as a parameter, requires a
    username and password

    Returns
    ---------
    User : JSON object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['collections']['users']):
        return flask.jsonify(error=err), 400

    json['password'] = auth.hash_password(json['password'])
    return flask.jsonify(db_client.users_add(json)), 200

# Edit existing User Protected API endpoint
@app.route('/users/edit', methods = ['PUT'])
@flask_jwt_extended.jwt_required()
def edit_user():
    """
    Function to edit an existing user in the database.

    Parameters
    ---------
    username : str

    Returns
    ---------
    User : JSON object
    (Will return false if nothing updated, or user not found by username)
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['edit_user']):
        return flask.jsonify(error=err), 400

    if 'password' in json['updates']:
        json['updates']['password'] = auth.hash_password(
            json['updates']['password']
        )
    result = db_client.users_update(
        {'username': json['username']},
        {'$set': json['updates']}
    )
    if result:
        return flask.jsonify(result[0]), 200
    return flask.jsonify(error='User not found'), 404

# Delete existing User Protected API endpoint
@app.route('/users/delete', methods = ['DELETE'])
@flask_jwt_extended.jwt_required()
def delete_user():
    """
    Function to delete an existing user in the database.

    Parameters:
    username : str
    
    Returns
    ---------
    data : JSON object
    """
    json = flask.request.get_json()
    if err := validate_json(json, schema['endpoints']['delete_user']):
        return flask.jsonify(error=err), 400

    if json['username'] == 'admin':
        return flask.jsonify(message="Can't delete user admin."), 405

    if db_client.users_delete({'username': json['username']}):
        return flask.jsonify(data='Delete Sucessful'), 200
    return flask.jsonify(error='User not found'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0')
