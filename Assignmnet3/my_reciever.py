import imaplib
import email
from email.utils import parsedate_to_datetime
import datetime

def fetch_unread_emails_and_save_print(username, password, target_date, filename='emails.txt'):
    try:
        # Connect to the IITD IMAP server
        mail = imaplib.IMAP4_SSL('mailstore.iitd.ac.in')
        mail.login(username, password)
        mail.select('inbox')  # Select the inbox folder

        # Format the target date for the IMAP search query
        target_date_str = target_date.strftime('%d-%b-%Y')

        # Search for unread emails from the specific date
        result, data = mail.search(None, f'(UNSEEN SENTON {target_date_str})')
        email_ids = data[0].split()

        with open(filename, 'w', encoding='utf-8') as file:
            for email_id in email_ids:
                result, data = mail.fetch(email_id, '(RFC822)')
                raw_email = data[0][1]
                msg = email.message_from_bytes(raw_email)

                # Print headers to terminal
                print("-" * 50)
                file.write("-" * 50 + "\n")
                for header, value in msg.items():
                    print(f"{header}: {value}")
                    file.write(f"{header}: {value}\n")

                # Print separator between headers and body
                print("-" * 50)
                file.write("-" * 50 + "\n")

                # Extract email content
                sender = msg['From']
                subject = msg['Subject']
                body = ""

                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if "text/plain" in content_type:
                            # Decode the payload explicitly with 'utf-8' encoding
                            body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                else:
                    # Decode the payload explicitly with 'utf-8' encoding
                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')

                # Print content to terminal
                print(f"From: {sender}")
                print(f"Subject: {subject}")
                print(f"Body:\n{body}")
                file.write(f"From: {sender}\n")
                file.write(f"Subject: {subject}\n")
                file.write(f"Body:\n{body}\n\n")

                # Print separator between emails
                print("-" * 50)
                file.write("-" * 50 + "\n\n")

        print("Unread emails with headers and content saved to", filename, "and printed successfully!")

    except Exception as e:
        print("Error:", e)

# Replace with your IITD credentials
iitd_username = "jcs232565@iitd.ac.in"
iitd_password = "62762CJ3"

# Replace with the target date you want to retrieve unread emails for
target_date = datetime.datetime(2024, 3, 31)  # Example: March 31, 2024

# Specify the filename for output (optional)
filename = 'emails.txt'  # You can change this

# Fetch, save, and print unread emails
fetch_unread_emails_and_save_print(iitd_username, iitd_password, target_date, filename)
