def withdraw_safe(user_id, amount):
    with db.transaction():
        acc = Account.query.with_for_update().get(user_id)
        if acc.balance >= amount:
            acc.balance -= amount
