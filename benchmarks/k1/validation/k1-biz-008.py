def fulfill_order_safe(order_id):
    order = Order.query.get(order_id)
    if order.state != "PAID":
        raise InvalidStateError("Order not paid")
    ship_package(order)
