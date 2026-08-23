def execute_withdrawal(acc_id, qty):
    # Race condition
    acc = Account.query.get(acc_id)
    if acc.balance >= qty:
        acc.balance -= qty
        db.commit()
