Bcrypt Password Tool

A Python-based command-line tool for hashing, verifying, and guessing passwords using the bcrypt algorithm. This tool provides a user-friendly interface with rich console output, leveraging the bcrypt and rich libraries to perform secure password hashing and verification tasks.

Features





Hash Passwords: Generate bcrypt hashes for passwords with customizable cost factors (4-31).



Verify Passwords: Check if a password matches a given bcrypt hash.



Guess Passwords: Attempt to guess a password from a bcrypt hash using a provided password list file.



Interactive CLI: User-friendly interface with colorful, formatted output using the rich library.



Error Handling: Robust error handling for invalid inputs, file operations, and bcrypt processes.

Requirements





Python 3.6 or higher



Required Python packages:





bcrypt



rich

Installation





Clone the Repository:

git clone https://github.com/your-username/bcrypt-password-tool.git
cd bcrypt-password-tool



Set Up a Virtual Environment (recommended):

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate



Install Dependencies:

pip install bcrypt rich

Usage

Run the script using Python:

python bcrypt_tool.py

Available Options

Upon running the script, you’ll be presented with a menu:





Hash a Password: Enter a password and a cost factor (4-31, default 10) to generate a bcrypt hash.



Verify a Password: Provide a bcrypt hash and a password to check if they match.



Guess Password from Hash: Supply a bcrypt hash and a path to a password list file to attempt guessing the password.



Exit: Close the program.

Example Workflow





Hashing a Password:





Select option 1.



Enter a password (e.g., mysecretpassword).



Specify a cost factor (e.g., 12).



Output: A bcrypt hash like $2b$12$....



Verifying a Password:





Select option 2.



Enter the bcrypt hash (e.g., $2b$12$...).



Enter the password to verify (e.g., mysecretpassword).



Output: Confirmation of whether the password matches the hash.



Guessing a Password:





Select option 3.



Enter the bcrypt hash.



Provide the path to a password list file (e.g., passwords.txt with one password per line).



Output: The matching password if found, or a message indicating no match.

Example Password List File

Create a file (e.g., passwords.txt) with one password per line:

password123
mysecretpassword
testpass

Notes





The bcrypt cost factor determines the computational complexity of the hash. Higher values increase security but take longer to compute.



Ensure the password list file for guessing is a plain text file with one password per line.



This tool is intended for educational and ethical purposes only. Do not use it for unauthorized password cracking.

License

This project is licensed under the MIT License. See the LICENSE file for details.

Contributing

Contributions are welcome! Please open an issue or submit a pull request with improvements or bug fixes.

Contact

Created by Mahdi Riahi. For questions or suggestions, open an issue on this repository.
