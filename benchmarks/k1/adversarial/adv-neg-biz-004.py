def fulfill_order_safe(order_id):
    order = Order.query.get(order_id)
    if order.state != "PAID":
        raise InvalidStateError("Not paid")
    ship_item(order)
