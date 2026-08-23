def checkout_safe(product_id):
    product = Product.query.get(product_id)
    return charge_card(product.unit_price)
