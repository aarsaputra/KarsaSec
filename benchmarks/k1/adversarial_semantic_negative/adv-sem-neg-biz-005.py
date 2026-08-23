def fulfill_order_state_and_owner_guarded(order_id, current_user):
    order = Order.query.filter_by(id=order_id, owner_id=current_user.id).first()
    if order.state != "PAID":
        raise InvalidStateError("Order not paid")
    ship_item(order)
