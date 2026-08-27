def merge_dict(target, source):
    for key, value in source.items():
        setattr(target, key, value)
    return target
