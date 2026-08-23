def calculate_qty_safe(req):
    qty = req.json.get("quantity")
    if qty <= 0:
        raise ValueError("Invalid qty")
    return qty * 100
