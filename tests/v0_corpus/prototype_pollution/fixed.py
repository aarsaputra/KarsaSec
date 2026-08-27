def merge_dict(target, source):
    for key, value in source.items():
        if key in ("__proto__", "constructor", "prototype"):
            continue
        target[key] = value
    return target
