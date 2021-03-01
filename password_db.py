"""
password_db offers numerous functions
to perform on SQLite database file 'userLogin.db'

Available functions:

create_db: creates database
add_user: adds user to db
add_user_from_webpage: functions as add_user, but takes in
                        username and password parameters
get_date: returns current date
hash_passwords: creates random salt and hashes
                salt and plaintext password together
                adding 40 character salt to the hash's
                beginning
query_db: creates a list of database rows to be checked
delete_from_db: deletes db rows
validate_password: takes in user password input and determines
                    if password is between 8 and 25 characters long
                    if password contains at least 1 capital letter
                    if password contains at least 1 lower case letter
                    if password contains at least one number
                    if password contains at least special character
create_user_password: creates user password 16 characters long that
                      satisfies conditions stated in validate_password
                      description

"""

import sqlite3
from datetime import datetime
import hashlib
from os import urandom
from base64 import b64encode
import random



def create_db():
    """ Create table users in userLogin database """
    try:
        conn = sqlite3.connect('userLogin.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE users
                    (
                    name text,
                    hash text,
                    clearance text,
                    date_created text, 
                    )''')
        conn.commit()
        return True
    except BaseException:
        return False
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def add_user():
    """ Insert new user and password to database """
    new_user_name = str(input("Please enter the name of your username: "))  # Need exception handling
    new_user_password = str(input("Enter a password: "))
    new_clearance_level = "bronze"
    # Hash password
    salt_n_hash = hash_passwords(new_user_password)
    new_user_date = str(get_date())
    data_to_insert = [(new_user_name, salt_n_hash, new_clearance_level, new_user_date)]
    try:
        conn = sqlite3.connect('userLogin.db')
        c = conn.cursor()
        prepared_statement = """INSERT INTO users VALUES (?, ?, ?, ?)"""
        c.executemany(prepared_statement, data_to_insert)
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error. Tried to add duplicate record!")
    else:
        print("Success")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def add_user_from_webpage(new_user_name, new_user_password):
    """
    takes input of username and password, uses hash_passwords method to
    hash passwords
    :param new_user_name:
    :param new_user_password:
    """
    new_clearance_level = "bronze" # lowest clearance level
    # Hash password
    salt_n_hash = hash_passwords(new_user_password)
    new_user_date = str(get_date())
    data_to_insert = [(new_user_name, salt_n_hash, new_clearance_level, new_user_date)]
    try:
        conn = sqlite3.connect('userLogin.db')
        c = conn.cursor()
        prepared_statement = """INSERT INTO users VALUES (?, ?, ?, ?)"""
        c.executemany(prepared_statement, data_to_insert)
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error. Tried to add duplicate record!")
    else:
        return True
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def get_date():
    """ Generate timestamp for data inserts """
    d = datetime.now()
    return d.strftime("%m/%d/%Y, %H:%M:%S")


def hash_passwords(plaintext_password):
    """
    hash passwords after creating 40 character long salt
    add salt to password and return result
    :param plaintext_password:
    :return: salt + password hash
    """
    salt_bytes = urandom(30)
    salt = b64encode(salt_bytes).decode('utf-8')
    # prepend salt to password and hash
    salted_hashable = salt + plaintext_password
    salted_hashable = salted_hashable.encode('utf-8')
    new_hash = hashlib.sha256(salted_hashable).hexdigest()
    return salt + new_hash


def query_db():
    """
    creates list of rows in database

    :return: list if rows from database file
    """
    try:
        conn = sqlite3.connect('userLogin.db')
        c = conn.cursor()
        user_list = []
        for row in c.execute("SELECT * FROM users"):
            user_list.append(row)
    except sqlite3.DatabaseError:
        print("Error. Could not retrieve data.")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            return user_list
            conn.close()


def delete_from_db():
    """ Delete Rows in Table"""
    try:
        conn = sqlite3.connect('userLogin.db')
        c = conn.cursor()
        user_list = []

        c.execute("DELETE FROM users")
        conn.commit()
        print("Data Base Cleared")

    except sqlite3.DatabaseError:
        print("Error. Could not retrieve data.")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            return user_list
            conn.close()


def validate_password(password):
    """
    Checks to see if user password has
    1 capital letter,
    1 special character.
    1 number
    1 lowercase letter
    and is between 8-25 characters long
    :param password: plaintext password entered by user
    :return: boolean
    """
    special_char_list = ["@", "#", "$", "%"]
    validate = False
    correct_length = False
    upper_case_letter = False
    lower_case_letter = False
    has_special_char = False
    has_digit = False
    if 8 <= len(password) <= 25:
        correct_length = True
    for character in password:
        if character.isupper() == True:
            upper_case_letter = True
        if character.islower():
            lower_case_letter = True
        if character.isdigit():
            has_digit = True
        for i in range(0, len(special_char_list)):
            if character == special_char_list[i]:
                has_special_char = True
    if correct_length == True and upper_case_letter == True and lower_case_letter == True \
            and has_special_char == True and has_digit == True:
        validate = True
    return validate


def create_user_password():
    """
    Creates a password for user that is 16 characters long,
    contains a special character,
    a number,
    and at least 1 capital letter
    :return: passW for autogenerated password
    """
    ALPHA = "abcdefghijklmnopqrstuvwxyz"
    SPECIAL_CHARS = "@#$%&"
    passW = ""
    num = 0
    special_char_choice = random.randint(0, 4)
    special_char_index = random.randint(0, 7)
    one = random.randint(0, 15)
    two = random.randint(0, 15)
    three = random.randint(0, 15)
    number_index = random.randint(8, 15)

    # generate random string 10 characters long and assign uppercase letters, a number, special character
    while num < 16:
        letter_index = random.randint(0, 25)
        letter = ALPHA[letter_index]
        if num == one or num == two or num == three:
            letter = letter.upper()

        if num == special_char_index:
            letter = SPECIAL_CHARS[special_char_choice]

        if num == number_index:
            letter = str(random.randint(1, 9))
        passW += letter
        num += 1
    return passW

