from check_password_pwned import check_password_pwned

if __name__ == "__main__":
    password = input("Enter your password to check: ")
    is_pwned, count = check_password_pwned(password)
    if is_pwned:
        print(f" This password has been found {count} times in data breaches!")
    else:
        print(" This password was NOT found in any known breaches.")
