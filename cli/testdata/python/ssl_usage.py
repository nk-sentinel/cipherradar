import ssl

def create_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

def insecure_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
