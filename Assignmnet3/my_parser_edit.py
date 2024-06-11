import re 

def parse_email_security_headers(email_headers):
    """Parses security-related information from email headers.

    Args:
        email_headers: A string containing the email header data.

    Returns:
        A dictionary containing parsed security information. Keys are security protocol names, 
        and values are either the extracted data or "Not found" if not present.
    """

    security_protocols = {
        'TLS Info': r'using\s+TLSv[\d.]+\s+with\s+cipher\s+[A-Za-z0-9_\-]+\s+\(\d+/\d+\s+bits\)',
        'X Virus Scanned': r'X-Virus-Scanned:(.*?)(?=;|$)',
        'SPF': r'Received-SPF:\s*(.*?)(?=;|$)',
        'DMARC': r'DMARC:(.*?)(?=;|$)',
        'MIME': r'MIME(.*?)(?=;|$)',
        'IronPort-SDR': r'IronPort-SDR:(.?)(?=\n\s\S|$)',
        'IronPort-PHdr': r'IronPort-PHdr:(.?)(?=\n\s\S|$)',
        'DKIM': r'DKIM-Signature:',
    }

    # Dictionary to store the output
    output = {}

    # Search for each value in the email headers and store the matches
    for key, value in security_protocols.items():
        matches = re.findall(value, email_headers, re.MULTILINE )
        if matches:
            # Join multiple matches with a newline character for readability
            output[key] = '\n'.join(matches)
        else:
            output[key] = 'Not found'

    # Count the number of DKIM signatures
    dkim_count = len(re.findall(security_protocols['DKIM'], email_headers))

    # Add DKIM count to the output
    output['DKIM Count'] = dkim_count

    return output

if __name__ == "__main__":
    print("Details from emails.txt for GMAIL HEADER:")
    with open(f"emails_gmail.txt", "r") as file:
        email_headers = file.read()
    parsed_results = parse_email_security_headers(email_headers)

    for key, value in parsed_results.items():
        print(f"{key}:\n{value}\n")
