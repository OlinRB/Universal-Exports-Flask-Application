"""
db_functions offers two functions:

authenticate which compares a stored password
hash that has been salted using the sha256 algorithm
to a plaintext password. Function returns boolean

check_passwords utilizes authenticate function and checks if
password and username input are correct



"""
import hashlib
from password_db import query_db


def check_passwords(user, plaintext):
    """

    :param user:
    :param plaintext:
    :return: username and clearance level
    Function checks user login database file using query_db() from
    password_db.py for user, if user is found and passwords match
    (tested using authenticate() function) function returns username
    and clearance level
    """
    login_list = query_db()
    for person in login_list:
        username = person[0]
        hashed_pass = person[1]
        credential = person[2]
        if username == user and authenticate(hashed_pass, plaintext) == True:
            return username, credential


def authenticate(stored, plain_text, salt_length=None) -> bool:
    """tests password by removing salt from stored password hash,
    adding salt to plaintext password input, hashing, and comparing
    to stored password.

    :param stored: str (salt + hash retrieved from database)
    :param plain_text: str (user-supplied password)
    :param salt_length: int
    :return: bool
    """


    salt_length = salt_length or 40  # set salt_length
    salt = stored[:salt_length]  # extract salt from stored value
    stored_hash = stored[salt_length:]  # extract hash from stored value
    hashable = salt + plain_text  # concatenate hash and plain text
    hashable = hashable.encode('utf-8')  # convert to bytes
    this_hash = hashlib.sha256(hashable).hexdigest()  # hash and digest
    return this_hash == stored_hash  # compare
