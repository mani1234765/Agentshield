from authorization import TrustedIdentity, ApprovalDecision, authorize_action

def test_intern_cannot_delete_even_with_approval():
    identity = TrustedIdentity(
        user_id="user_101",
        agent_id="claude_agent_01",
        role="intern",
    )

    approval = ApprovalDecision(
        approved=True,
        approved_by="admin_001",
    )

    assert authorize_action(
        identity, "delete", approval
    ) is False

def test_admin_cannot_delete_without_approval():
    identity = TrustedIdentity(
        user_id="user_103",
        agent_id="claude_agent_01",
        role="admin",
    )

    approval = ApprovalDecision(approved=False)

    assert authorize_action(
        identity, "delete", approval
    )is False

def test_admin_can_delete_with_approval():
    identity = TrustedIdentity(
        user_id="user_103",
        agent_id="cluade_agent_01",
        role="admin",
    )

    approval = ApprovalDecision(
        approved=True,
        approved_by="admin_001",
    )

    assert authorize_action(
        identity, "delete", approval
    ) is True
