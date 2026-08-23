def apply_coupon_single_use_guarded(req, user_id, code):
    coupon = Coupon.query.filter_by(code=code).first()
    if coupon.is_used:
        raise InvalidCouponError("Coupon already used")
    coupon.mark_used(user_id)
    return apply_discount(coupon)
