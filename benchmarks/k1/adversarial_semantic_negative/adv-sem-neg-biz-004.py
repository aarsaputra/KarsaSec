def withdraw_with_pessimistic_transaction_lock(user_id, qty):
    with db.transaction():
        acc = Account.query.with_for_update().get(user_id)
        if acc.balance >= qty:
            acc.balance -= qty
            db.commit()
