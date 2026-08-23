def apply_discount(cart, coupon_code):
    coupon = Coupon.query.filter_by(code=coupon_code).first()
    cart.total -= coupon.discount
