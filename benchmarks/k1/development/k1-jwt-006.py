def secure_verify(token, key):
    verifier = JWTVerifier(key, allowed_algs=["RS256"])
    return verifier.verify(token)
