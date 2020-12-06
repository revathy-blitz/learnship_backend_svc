import re


def validate_email_addr(email: str):
    if not isinstance(email, str):
        return False

    if len(email.split('@')) < 2:
        return False

    regex_result = re.search(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email)

    return bool(regex_result)


def validate_password(password: str) -> bool:
    if len(password) < 10:
        return False

    pword = set(password)
    lc_alpha = set(''.join([chr(x) for x in range(97, 123)]))
    uc_alpha = set(''.join([chr(x) for x in range(65, 91)]))
    numeric = set(''.join([chr(x) for x in range(48, 58)]))
    symbols = ''.join([chr(x) for x in range(32, 48)])
    symbols += ''.join([chr(x) for x in range(58, 65)])
    symbols += ''.join([chr(x) for x in range(91, 97)])
    symbols += ''.join([chr(x) for x in range(123, 127)])
    symbols_set = set(symbols)

    char_sets = [lc_alpha, uc_alpha, numeric, symbols_set]

    for char_set in char_sets:
        if len(char_set.intersection(pword)) < 1:
            return False

    return True
