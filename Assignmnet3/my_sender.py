import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

def send_email(sender_email, sender_password, receiver_email):
    # Email content
    body = "The OTP for transferring Rs 1,00,000 to your friend’s account is 256345."
    subject = "OTP for Fund Transfer"

    # Create a MIMEText object for the email content
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)  # Add Date header
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Establish a connection to the SMTP server
        with smtplib.SMTP_SSL('smtp.iitd.ac.in', 465) as server:  # IITD SMTP server and port with TLS
            # server.starttls()  # Start TLS encryption
            server.login(sender_email, sender_password)  # Login to the email server
            text = msg.as_string()
            # Send the email
            server.sendmail(sender_email, receiver_email, text)
            print("Email sent successfully!")
            server.quit()
    except Exception as e:
        print("Error:", e)

# Sender's IITD webmail credentials
sender_email = "jcs232565@iitd.ac.in"
sender_password = "62762CJ3"

# Receiver's IITD webmail credentials
receiver_email = "jcs232565@iitd.ac.in"

# Send the email
send_email(sender_email, sender_password, receiver_email)

