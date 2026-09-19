from src.detector import analyze_url

TEST_CASES = [
    ("https://www.google.com", "Legitimate"),
    ("https://github.com/login", "Legitimate"),
    ("https://www.microsoft.com/en-us", "Legitimate"),
    ("https://example.com/account", "Legitimate"),
    ("http://192.168.1.50/login", "Phishing"),
    ("http://secure-login-verify-account.example.com", "Phishing"),
    ("http://example.com@198.51.100.7/login", "Phishing"),
    ("http://verify-account-password.example.com/login?confirm=1&secure=1", "Phishing"),
    ("https://login.example.com", "Suspicious"),
    ("http://tinyurl.com/abc123", "Suspicious"),
    ("https://example.com/verify", "Suspicious"),
    ("https://www.example.com/products", "Legitimate"),
    ("http://account-update.example.com/secure/login", "Suspicious"),
    ("https://sub1.sub2.example.com/page", "Suspicious"),
    ("http://example.com/a-b-c-d/e=f&g=h", "Suspicious"),
]

def run_tests():
    print("URL | Expected | Actual | Score")
    print("-" * 80)
    correct = 0
    for url, expected in TEST_CASES:
        result = analyze_url(url)
        actual = result["label"]
        correct += int(actual == expected)
        print(f"{url} | {expected} | {actual} | {result['score']}")
    print(f"\nAccuracy on hand-written test set: {correct/len(TEST_CASES):.2%}")

if __name__ == "__main__":
    run_tests()
