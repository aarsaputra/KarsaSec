def apply_discount_safe(cart, coupon_code, user):
    coupon = Coupon.query.filter_by(code=coupon_code, is_used=False).first_or_404()
    cart.total -= coupon.discount
    coupon.is_used = True
    db.commit()
