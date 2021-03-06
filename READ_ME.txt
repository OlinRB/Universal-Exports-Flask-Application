Olin Ruppert-Bousquet
CS166

Universal Exports Flask Application

The Universal Exports Application is a login based application with 3 different clearance levels, gold, silver, and
bronze. Users with gold clearance have access to 5 different links inside the menu. Users with silver clearance
are allowed 4 links in the menu, and users with bronze clearance are allowed two links.

Running Universal Exports:
    Begin by installing flask: go to terminal and run command 'pip install flask'
    Then, run the program run.py. This will launch the server with the url
    http://localhost:24007/. The folder containing all of the files for Universal Exports already contains a database
    with login information (one user for each clearance level) for this application.

Navigating Universal Exports:
    Upon launching Universal Exports, users will be navigated to the home page. Here, users have the option to login, or
    register a new account.
        For existing account login:
            Clearance level gold:
                Username: JamesB  Password: $ecreT007
            Clearance level silver:
                Username: Q  Password: Boothroyd1914%
            Clearance level bronze:
                Username: MoneyP  Password: mi6Eve#1927

            ** After 3 failed login attempts, the session is locked and no pages can be accessed **
            ** Server must be restarted to attempt to login again **
    For user registration:
        When users click on REGISTER, they are transferred to the register page where they are presented with
        two options: Autogenerate Password, or Choose My Own as clickable buttons.
        If user chooses Autogenerate Password:
            User is prompted to enter username, and password is autogenerated and printed to the login_success page.
        If user clicks Choose My Own:
            User is prompted to enter a username and password. The password must be between 8-25 characters long, and
            contain at least one number, capital letter, and special character (@#$%&). If entered password fails to meet
            requirements, message is flashed and user must enter acceptable password.
        Username and password are added to the database and clearance level set to a default of bronze.

    After successful login/registration, user is taken to the login_success page. On the left is a list menu of the
    available pages. Menu choices determined by clearance level.
    Once a menu link is clicked, the user can return to the main menu by clicking MAIN MENU in the top left corner of
    the page.

    ** UNIVERSAL EXPORTS page within main menu holds a secret transmission (audio file, make sure audio settings on
    device are set accordingly). This page is only accessible by users with clearance level gold.

    Under the menu is a logout link that will log the user out.

    Security considerations:
        Because flask uses Jinja2 as its template engine, user input is automatically escaped which prevents
        user input cross site scripting attacks.

        Because there are no imported files (scripts, css, etc), there is no required integrity check for files.

        SQL statements in Universal Exports utilize prepared statements to stop the threat of SQL injection.

        Because user is limited to 3 login attempts, brute force password/username testing on client side browser
        interface not possible.


Acknowledgements:
    Professor Eddy and bank.py application for reference and inspiration
    stack overflow user 'furas' for information for javascript onclick method to create play button for audio file
                        * To avoid necessity of basic <audio controls> interface (Visual upgrade)
    bootstrap css for providing style to text input boxes with Universal Exports (as seen in bank.py)
    w3schools.com for html/css reference material

    Special thanks to Ian Fleming.