def withdraw_safe(user_id, qty):
    with db.transaction():
        acc = Account.query.with_for_update().get(user_id)
        if acc.balance >= qty:
            acc.balance -= qty
