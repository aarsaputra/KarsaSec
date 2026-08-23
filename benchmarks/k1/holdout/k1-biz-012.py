def calculate_total_safe(price, req_qty):
    if req_qty <= 0 or req_qty > 100:
        raise ValueError("Invalid quantity")
    return price * req_qty
