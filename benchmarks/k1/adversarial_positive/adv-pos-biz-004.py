def process_fulfillment(order_id):
    # Workflow bypass
    order = Order.query.get(order_id)
    ship_item(order)
