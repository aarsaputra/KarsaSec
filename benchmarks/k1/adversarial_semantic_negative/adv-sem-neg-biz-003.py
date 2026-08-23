def get_user_doc_owner_validated(req, doc_id, current_user):
    doc = Document.query.filter_by(id=doc_id, owner_id=current_user.id).first()
    if not doc:
        raise PermissionDenied("Unauthorized document access")
    return doc.content
