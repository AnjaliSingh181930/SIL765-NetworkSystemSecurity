import re

def extract_security_indicators(email_header):
    """Extracts common indicators of email-based security threats from the email header.

    Args:
        email_header (str): The email header as a string.

    Returns:
        list: A list of common security threat indicators found in the email header.
    """
    indicators = []

    # Mismatched sender addresses or domain names
    sender_address = re.search(r'From:\s*(.*?)\n', email_header)
    if sender_address:
        sender_address = sender_address.group(1)
        if '@' in sender_address:
            sender_domain = sender_address.split('@')[1]
            if 'iitd.ac.in' not in sender_domain:
                indicators.append("Mismatched sender domain")

    # Inconsistent message IDs or date and time stamps
    message_id = re.search(r'Message-Id:\s*(.*?)\n', email_header)
    date_stamp = re.search(r'Date:\s*(.*?)\n', email_header)
    if message_id and date_stamp:
        message_id = message_id.group(1)
        date_stamp = date_stamp.group(1)
        if 'GMT' not in date_stamp or message_id not in email_header:
            indicators.append("Inconsistent message ID or date and time stamp")

    # Unusual content type or encoding
    content_type = re.search(r'Content-Type:\s*(.*?)\n', email_header)
    if content_type:
        content_type = content_type.group(1)
        if 'multipart' not in content_type.lower() or 'base64' not in content_type.lower():
            indicators.append("Unusual content type or encoding")

    # Missing encryption, authentication, or verification protocols
    if 'DKIM-Signature' not in email_header or 'Received-SPF' not in email_header:
        indicators.append("Missing encryption, authentication, or verification protocols")

    # Multiple hops or relays in the message route
    if email_header.count('Received:') > 1:
        indicators.append("Multiple hops or relays in the message route")

    # Links or attachments that do not match the subject or context of the message
    subject = re.search(r'Subject:\s*(.*?)\n', email_header)
    if subject:
        subject = subject.group(1)
        if 'OTP' in subject:
            if 'http' in email_header or 'attachment' in email_header:
                indicators.append("Suspicious links or attachments in OTP email")

    return indicators

if __name__ == "__main__":
    with open("emails_gmail.txt", "r") as file:
        email_header = file.read()

    security_indicators = extract_security_indicators(email_header)

    print("Common Indicators of Email-Based Security Threats in GMAIL HEADER:")
    for indicator in security_indicators:
        print("- " + indicator)
