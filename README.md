🔐 Secure Coding Web Application

A secure web application built with Python and Flask that demonstrates common web security vulnerabilities and their mitigation using secure coding practices.

This project was developed to showcase practical implementation of secure authentication, input validation, password hashing, and SQL injection prevention in a real web application environment.

The goal is to illustrate how insecure implementations can lead to vulnerabilities and how developers can protect applications using modern defensive programming techniques.

📚 Project Overview

Web applications are frequently targeted by attackers due to insecure coding practices.

This project demonstrates:

How common vulnerabilities occur

How they can be exploited

How they can be prevented using secure development techniques

The system includes a working authentication platform with a backend database, designed to highlight secure vs insecure approaches to user management and database interaction.

⚙️ Technologies Used

Python

Flask

MySQL

HTML / CSS

SQL

XAMPP (local MySQL server)

🔑 Security Concepts Demonstrated

This project focuses on important web security principles including:

Authentication Security

Secure user login and registration

Password hashing instead of plain-text storage

SQL Injection Protection

Use of parameterized queries

Prevention of malicious database manipulation

Input Validation

Server-side validation of user inputs

Protection against malformed data

Secure Database Interaction

Safe query execution

Separation between application logic and database operations

Session Management

Proper session handling for authenticated users

🚀 Features

User Registration System

Secure Login Authentication

Password Hashing

MySQL Database Integration

SQL Injection Protection

Secure Input Handling

Modular Flask Application Structure

📁 Project Structure
SecureCodingProject
│
├── app.py                 # Main Flask application
├── db_setup.py            # Database initialization script
│
├── templates/             # HTML templates
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
│
├── static/                # Static files (CSS / assets)
│   └── styles.css
│
└── database/
    └── schema.sql         # Database schema
🖥️ Running the Project Locally
1️⃣ Clone the repository
git clone https://github.com/YOUR_USERNAME/SecureCodingProject.git
cd SecureCodingProject
2️⃣ Install dependencies
pip install flask mysql-connector-python
3️⃣ Start MySQL

Start MySQL using XAMPP or any local MySQL server.

4️⃣ Setup the database
python db_setup.py
5️⃣ Run the application
python app.py
6️⃣ Open the application

Navigate to:

http://localhost:5000
🎯 Educational Purpose

This project was created to demonstrate secure software development practices and provide a practical example for developers learning about:

Web application security

Secure authentication systems

SQL injection prevention

Defensive programming

👨‍💻 Author

Daniel Shany
Computer Science Graduate

⭐ Possible Future Improvements

CSRF protection

Rate limiting for login attempts

JWT authentication

Password strength validation

HTTPS enforcement

Docker deployment

If you want, I can also help you add 3 things that make recruiters immediately impressed with GitHub projects:

1️⃣ Security attack demo section (shows you understand vulnerabilities deeply)
2️⃣ Architecture diagram
3️⃣ Screenshots of the app

These make the project look much more professional and portfolio-level, which helps when applying for software jobs.
