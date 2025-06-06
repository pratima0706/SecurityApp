@staticmethod
def generate_alphanumeric_captcha():
    import string
    chars = string.ascii_letters + string.digits
    answer = ''.join(random.choices(chars, k=6))
    return f"Enter: {answer}", answer
