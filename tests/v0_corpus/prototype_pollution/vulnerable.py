def merge_dict(target, source):
    for key, value in source.items():
        if key == "__proto__" or key == "constructor":
            setattr(target, key, value)
        else:
            target[key] = value
    return target
