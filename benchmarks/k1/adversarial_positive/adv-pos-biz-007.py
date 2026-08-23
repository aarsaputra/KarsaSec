def checkout_cart(req):
    # Client price manipulation
    price = req.json.get("price")
    return create_charge(price)
