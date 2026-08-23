def get_document_safe(doc_id, current_user):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first_or_404()
    return doc.content
