"""Functions for exporting documents to CSV.

Export function names should be formatted as 'export_<document type>'.
This is so that export functions can be retrieved via getattr().
"""

import pandas as pd

def product_convert_nested(product):
    """Converted count and amount fields to single value.

    Args:
      product: Original product document.
    """
    if 'count' in product:
        product['count'] = (f"{product['count']['num']}"
                            f"{product['count']['unit']}")
    if 'amount' in product:
        product['amount'] = (f"{product['amount']['measurement']}"
                             f"{product['amount']['unit']}")

def export_project(project, db_client):
    """Export project to CSV.

    Args:
      project: Project to export.
      db_client: Client for database operations.

    Returns:
      CSV as a string.
    """
    products = db_client.products_get({'upc': {'$in': project['products']}})
    print(products)
    drc_upc = []
    for product in products:
        product_convert_nested(product)
        if 'drc_upc' in product:
            drc_upc.append(product['drc_upc'])

    drc = db_client.products_get({'upc': {'$in': drc_upc}})
    for product in drc:
        product_convert_nested(product)
    products += drc

    df = pd.DataFrame(products)
    return df.to_csv(index=False, errors='backslashreplace')

def export_category(category, db_client):
    """Export category to CSV.

    Args:
      category: Category to export.
      db_client: Client for database operations.

    Returns:
      CSV as a string.
    """
    templates = db_client.templates_get(
        {'name': {'$in': category['templates']}}
    )
    df = pd.DataFrame(templates)
    return df.to_csv(index=False, errors='backslashreplace')
