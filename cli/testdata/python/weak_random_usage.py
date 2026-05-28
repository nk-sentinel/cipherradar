import random


# Security-sensitive: should be flagged.
def weak_token():
    return random.randint(0, 999999)


def weak_password(length=16):
    return "".join(random.choice("abcdef") for _ in range(length))


# Non-security use: must NOT be flagged (zero false positives).
def shuffle_deck(deck):
    random.shuffle(deck)
    return deck


def pick_color():
    return random.choice(["red", "green", "blue"])
