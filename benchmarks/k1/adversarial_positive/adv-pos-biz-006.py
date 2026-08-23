def calculate_order_sum(req):
    # Unvalidated quantity
    qty = req.json.get("quantity")
    return qty * 100
