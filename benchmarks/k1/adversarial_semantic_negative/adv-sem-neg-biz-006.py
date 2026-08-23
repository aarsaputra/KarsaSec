def calculate_total_quantity_range_guarded(req):
    qty = req.json.get("quantity")
    if not isinstance(qty, int) or qty <= 0:
        raise ValueError("Quantity must be positive integer")
    return qty * 100
