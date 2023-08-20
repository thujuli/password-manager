from project import get_password, menu, get_user_credentials, check_id_in_credentials


def test_get_passoword(monkeypatch):
    inputs1 = iter(["123", "123"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs1))
    assert get_password() == "123"

    inputs2 = iter(["test", "test"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs2))
    assert get_password() == "test"

    inputs3 = iter(["hello", "hello"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs3))
    assert get_password() == "hello"


def test_menu(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "3")
    assert menu() == "3"

    monkeypatch.setattr("builtins.input", lambda _: "1")
    assert menu() == "1"

    monkeypatch.setattr("builtins.input", lambda _: "5")
    assert menu() == "5"


def test_get_credentials(monkeypatch):
    inputs1 = iter(["google.com", "julianta", "hello", "hello"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs1))
    assert get_user_credentials() == {
        "site": "google.com",
        "username": "julianta",
        "password": "hello",
    }

    inputs2 = iter(["facebook.com", "thuujuli", "world", "world"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs2))
    assert get_user_credentials() == {
        "site": "facebook.com",
        "username": "thuujuli",
        "password": "world",
    }

    inputs3 = iter(["youtube.com", "thu_juli", "foo", "foo"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs3))
    assert get_user_credentials() == {
        "site": "youtube.com",
        "username": "thu_juli",
        "password": "foo",
    }


def test_id_in_credentials():
    credentials = [
        {"id": 1, "site": "google.com", "username": "julianta", "password": "hello"},
        {"id": 2, "site": "facebook.com", "username": "thuujuli", "password": "world"},
        {"id": 3, "site": "youtube.com", "username": "thu_juli", "password": "foo"},
    ]

    assert check_id_in_credentials(credentials, "1") == 1
    assert check_id_in_credentials(credentials, "2") == 2
    assert check_id_in_credentials(credentials, "hello") == False
