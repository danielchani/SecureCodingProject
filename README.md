
# 🔐 Secure Coding Web Application

A secure web application built with **Python and Flask** that
demonstrates common web security vulnerabilities and their mitigation
using secure coding practices.

This project showcases practical implementation of **secure
authentication, input validation, password hashing, and SQL injection
prevention** in a real web application environment.

------------------------------------------------------------------------

# 📚 Project Overview

Web applications are frequent targets of cyber attacks due to insecure
coding practices.

This project demonstrates:

-   How common vulnerabilities occur
-   How they can be exploited
-   How they can be prevented using secure development techniques

The system includes a working **authentication platform with backend
database integration**, designed to highlight secure vs insecure
approaches to user management and database interaction.

------------------------------------------------------------------------

# ⚙️ Technologies Used

-   Python
-   Flask
-   MySQL
-   HTML / CSS
-   SQL
-   XAMPP (local MySQL server)

------------------------------------------------------------------------

# 🔑 Security Concepts Demonstrated

## Authentication Security

-   Secure user login and registration
-   Password hashing instead of plain-text storage

## SQL Injection Protection

-   Use of parameterized queries
-   Prevention of malicious database manipulation

## Input Validation

-   Server-side validation of user inputs
-   Protection against malformed or malicious data

## Secure Database Interaction

-   Safe query execution
-   Separation between application logic and database operations

## Session Management

-   Proper session handling for authenticated users

------------------------------------------------------------------------

# 🚀 Features

-   User Registration System
-   Secure Login Authentication
-   Password Hashing
-   MySQL Database Integration
-   SQL Injection Protection
-   Secure Input Handling
-   Modular Flask Application Structure

------------------------------------------------------------------------

# 📁 Project Structure

    SecureCodingProject
    │
    ├── app.py
    ├── db_setup.py
    │
    ├── templates/
    │   ├── login.html
    │   ├── register.html
    │   └── dashboard.html
    │
    ├── static/
    │   └── styles.css
    │
    └── database/
        └── schema.sql

------------------------------------------------------------------------

# 🖥️ Running the Project Locally

### 1. Clone the repository

``` bash
git clone https://github.com/YOUR_USERNAME/SecureCodingProject.git
cd SecureCodingProject
```

### 2. Install dependencies

``` bash
pip install flask mysql-connector-python
```

### 3. Start MySQL

Start MySQL using **XAMPP** or any local MySQL server.

### 4. Setup the database

``` bash
python db_setup.py
```

### 5. Run the application

``` bash
python app.py
```

### 6. Open the application

Go to:

    http://localhost:5000

------------------------------------------------------------------------

# 🎯 Educational Purpose

This project demonstrates **secure software development practices** and
provides a practical example for developers learning about:

-   Web application security
-   Secure authentication systems
-   SQL injection prevention
-   Defensive programming

------------------------------------------------------------------------

