def withdraw(user_id, amount):
    acc = Account.query.get(user_id)
    if acc.balance >= amount:
        acc.balance -= amount
        db.commit()
