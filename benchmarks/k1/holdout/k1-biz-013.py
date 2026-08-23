def checkout(req):
    unit_price = req.json.get("unit_price")
    return charge_card(unit_price)
