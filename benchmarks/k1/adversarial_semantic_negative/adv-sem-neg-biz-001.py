def checkout_database_price_lookup(req):
    prod_id = req.json.get("product_id")
    product = Product.query.get(prod_id)
    return charge_card(product.price)
