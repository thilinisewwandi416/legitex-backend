import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(recipient_email, otp):
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT'))
    smtp_user = os.environ.get('SMTP_USER') 
    smtp_password = os.environ.get('SMTP_PASSWORD')

    subject = "Your Legitex Password Reset OTP"
    body = f"""
    <h3>Password Reset Request</h3>
    <p>Your OTP for resetting the password is:</p>
    <h2>{otp}</h2>
    <p>This code will expire in 5 minutes.</p>
    """

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            print(f" OTP email sent to {recipient_email}")
    except Exception as e:
        print(f" Failed to send email: {e}")
        raise
