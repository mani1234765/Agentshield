from permission import check_permission

result1 = check_permission("intern", "read", False)
assert result1 is True
print("Test 1 passed!")

result2 = check_permission("intern", "delete", True)
assert result2 is False
print("Test 2 passed!")

result3 = check_permission("manager", "update", False)
assert result3 is True
print("Test 3 passed!")


result4 = check_permission("manager", "read", False)
assert result4 is True
print("Test 4 passed!")

result5 = check_permission("manager", "delete", True)
assert result5 is False
print("Test 5 passed!")


result6 = check_permission("admin", "delete", True)
assert result6 is True
print("Test 6 passed!")

result7 = check_permission("admin", "delete", False)
assert result7 is False
print("Test 7 passed!")

test_cases = [
    ("intern", "read", False, True),
    ("intern", "delete", True, False),
    ("manager", "delete", True, False),
    ("manager", "update", False, True),
    ("manager", "read", False, True),
    ("admin", "delete", True, True),
    ("admin", "delete", False, False)
]

for role, action, approved, expected in test_cases:
    result = check_permission(role, action, approved)
    assert result is expected

print("Loop-based tests passed!")
