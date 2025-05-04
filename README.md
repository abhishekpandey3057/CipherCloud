# CipherCloud

# Secure Cloud File Storage System

[![Status](https://img.shields.io/badge/Status-Complete-brightgreen.svg)](https://github.com/your-username/your-repo-name)
[![Python Version](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-%E2%98%91%EF%B8%8F0.12+-brightgreen.svg)](http://flask.pocoo.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This project implements a secure cloud-based file storage system with end-to-end encryption and role-based access. It allows users to securely share files with specific recipients through OTP email verification.

## Features

-   **🔐 End-to-end Encrypted File Sharing:** Utilizes AES-256 for file content encryption and RSA for encrypting the AES key, ensuring only the intended recipient can decrypt the file.
-   **📩 OTP Email Verification:** Implements One-Time Password (OTP) verification via email for user signup, enhancing security.
-   **☁️ Cloud Storage with AWS S3:** Stores encrypted files securely in an Amazon S3 bucket.
-   **🧾 Metadata Management with DynamoDB:** Stores file metadata, including the encrypted AES key and recipient information, in an Amazon DynamoDB table.
-   **👥 Role-Based Dashboards:** Provides separate dashboards for senders and recipients, offering role-specific functionalities.
-   **✅ Dynamic Recipient Email:** Senders can specify the recipient's email address during file upload, ensuring files are shared with the correct user.

## Prerequisites

Before you begin, ensure you have the following installed and configured:

-   **Python 3.10+:** Download from [https://www.python.org/downloads/](https://www.python.org/downloads/)
-   **pip:** Python package installer (usually included with Python installations)
-   **OpenSSL:** For generating RSA key pairs. Installation instructions vary by operating system.
-   **AWS CLI:** For interacting with AWS services. Follow the installation guide at [https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
-   **(Optional) Git:** For version control. Download from [https://git-scm.com/downloads](https://git-scm.com/downloads)

## Setup

Follow these steps to set up and run the application locally:

### 1. Clone the Repository (Optional)

If you have Git installed, you can clone the repository:

`git clone <repository-url>`
`cd <repository-directory>`


### 2. Set Up Python Virtual Environment
Create and activate a virtual environment to isolate project dependencies:


`python -m venv venv`
`# Activate the environment`
`# Windows:`
`**venv\Scripts\activate**`
`# macOS/Linux:`
`**source venv/bin/activate**`


### 3. Install Required Python Libraries
Install the necessary Python packages using pip:
``pip install -r requirements.txt``

(If you haven't already, you can generate this file using pip freeze > requirements.txt)


### 4. Configure AWS CLI

Configure your AWS credentials using the AWS CLI:
``aws configure``

You will be prompted to enter your Access Key ID, Secret Access Key, default region (ap-south-1), and output format (you can leave the output format blank).


### 5. Create AWS Resources
S3 Bucket:Create an S3 bucket named secure-file-storage-bucket in the ap-south-1 region. Enable AES256 encryption for the bucket.
DynamoDB Table: Create a DynamoDB table named FileMetadata with file_id (String) as the primary key.


### 6. Set Up Gmail App Password
Enable 2-Step Verification for your Gmail account.

Go to https://myaccount.google.com/apppasswords and generate an app password for "Mail".

Update the following lines in app.py with your Gmail address and the generated app password:

``app.config['MAIL_USERNAME'] = 'your-email@gmail.com'``

``app.config['MAIL_PASSWORD'] = 'your-app-password'``


### 7. Generate RSA Key Pair - ( Delete the keys from the ``/keys`` folder and generate new one )

Create a keys/ directory and generate the RSA private and public keys:
``mkdir keys``

``openssl genrsa -aes256 -out keys/recipient_private.pem 2048``
Generate RSA Private Key (PEM format with encryption)

Enter a strong passphrase when prompted (e.g., Test@123)

``openssl rsa -in keys/recipient_private.pem -pubout -out keys/recipient_public.pem``
Generate Public Key from the Private Key

### Running the Application
To start the Flask development server:
``python app.py``

Visit http://127.0.0.1:5000 in your web browser to access the application.

### User Flow:

-- Signup: Navigate to /signup, enter your email, password, and select your role (Sender or Recipient). You will receive an OTP via email to verify your account.

-- Verify OTP: Go to /verify-otp and enter the received OTP. Upon successful verification, your user account with the selected role is created.

-- Login: Navigate to /login and enter your registered email and password. You will be redirected to the appropriate dashboard based on your role.

-- Sender Dashboard (/sender/dashboard):
    Upload a file.
    Enter the recipient's registered email address.
    Upon submission, the file is AES-encrypted, the AES key is RSA-encrypted using the recipient's public key, the encrypted file is uploaded to S3, and metadata (including the encrypted AES key and recipient email) is stored in DynamoDB.

-- Recipient Dashboard (/recipient/dashboard):
    View a list of files shared specifically with your email address.
    Click "Download" to retrieve a file.
    The system retrieves the encrypted file and AES key from S3 and DynamoDB, decrypts the AES key using your private key (using the passphrase you set during key generation), decrypts the file, and initiates a download.


### Deployment (Optional)

Option A: AWS EC2

    Launch an EC2 instance.
    
    Configure the security group to allow inbound traffic on port 5000.
    
    SSH into the instance.
    
    Install Python and other dependencies.
    
    Transfer your project files to the instance.
    
    Run the Flask application: python3 app.py. You might want to use a process manager like screen or tmux to keep the application running in the background.

Option B: Heroku

    Create a Procfile in your project root with the following content:
    ``web: python app.py``
    
    Create a Heroku application: heroku create.
    
    Push your code to Heroku: git push heroku main.
    
    Set the necessary configuration variables for your email credentials:
        ``heroku config:set MAIL_USERNAME=your-email@gmail.com``
        ``heroku config:set MAIL_PASSWORD=your-app-password``


### Security Tips:

    AES-256 Encryption: Ensures strong encryption for file content.
    
    RSA Key Wrapping: Protects the AES encryption key during storage and transmission.
    
    OTP via Email: Adds an extra layer of security during user registration.
    
    Recipient-Specific File Sharing: Limits file access to intended users.
    
    Strong Passphrase for Private Key: Protects the recipient's private RSA key. Remember the passphrase you used during private key generation (e.g., abhi@3057), as it will be required for decryption.


### Further Enhancements:

    🐳 Docker Support: Containerize the application for easier deployment and management.

    🧾 GitHub README: (You're looking at it!)

    🧪 File Validation or Expiration: Implement checks for file types and sizes, or set expiration dates for shared files.

    🔐 Secure Keys using AWS Secrets Manager: Store and manage the RSA private key securely using AWS Secrets Manager instead of local files.


### Contributing:
    Feel free to contribute to this project by submitting issues or pull requests.


### License: This project is licensed under
