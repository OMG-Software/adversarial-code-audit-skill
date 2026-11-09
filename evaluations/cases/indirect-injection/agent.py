"""Synthetic assistant path and complete security contract.

model.propose_tool consumes user text and retrieved text. Its output is an
untrusted proposed action, which the dispatcher must authorize against user
intent. The interface permits any dict; it supplies no intent authorization.
For this review, treat proposed actions as attacker-influenced input, not as
proof of user approval. Whether any particular model follows a note is not
established here. All policy checks in the dispatcher are shown below.
"""

DOCUMENTS = {"private-draft": {"owner": "victim", "text": "private draft"}}


def summarize_note(model, user_text, retrieved_note):
    action = model.propose_tool(user_text, retrieved_note)
    return dispatch_as_victim(action)


def dispatch_as_victim(action):
    # Exact schema: one allow-listed tool, one string argument, no extra keys.
    if type(action) is not dict or set(action) != {"tool", "document_id"}:
        return "invalid schema"
    if action["tool"] != "delete_document" or type(action["document_id"]) is not str:
        return "invalid schema"
    document = DOCUMENTS[action["document_id"]]
    if document["owner"] != "victim":
        return "forbidden"
    del DOCUMENTS[action["document_id"]]
    return "deleted"
