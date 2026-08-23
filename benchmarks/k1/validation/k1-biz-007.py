def fulfill_order(order_id):
    order = Order.query.get(order_id)
    ship_package(order)
