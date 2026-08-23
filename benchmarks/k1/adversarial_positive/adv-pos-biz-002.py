def fetch_user_document(doc_identifier):
    # Horizontal IDOR
    doc = Document.query.get(doc_identifier)
    return doc.content
