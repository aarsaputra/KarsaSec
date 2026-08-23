def checkout_safe(req):
    prod_id = req.json.get("product_id")
    prod = Product.query.get(prod_id)
    return create_charge(prod.unit_price)
