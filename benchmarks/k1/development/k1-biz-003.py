def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return doc.content
