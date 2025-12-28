import imaplib
import email
import pickle
import re
import requests
import time

# === Config ===
EMAIL = 'phishguard.test@gmail.com'
EMAIL_PASSWORD = 'idft mhvg snyq dagn' 
IMAP_SERVER = 'imap.gmail.com'
VT_API_KEY = '1eaa451687ca9fb22c002db568ac0be233c83176e7dfd93c07b2e30d27fdfabe' 

# === Load ML model ===
with open('app/model/model.pkl', 'rb') as f:
    model = pickle.load(f)

# === VirusTotal enrichment ===
def enrich_with_virustotal(text):
    headers = {'x-apikey': VT_API_KEY}
    vt_results = []

    urls = [word for word in text.split() if word.startswith('http')]

    for url in urls:
        try:
            scan_req = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url}
            )
            scan_resp = scan_req.json()
            url_id = scan_resp['data']['id']

            report_req = requests.get(
                f'https://www.virustotal.com/api/v3/urls/{url_id}',
                headers=headers
            )
            report_resp = report_req.json()

            malicious_count = report_resp['data']['attributes']['last_analysis_stats']['malicious']
            vt_results.append({
                'url': url,
                'malicious': malicious_count > 0,
                'score': malicious_count
            })

        except Exception as e:
            vt_results.append({
                'url': url,
                'error': str(e)
            })

        time.sleep(15)  # Respect VT rate limits

    return vt_results

# === Fetch unread emails ===
def fetch_unread_emails():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL, EMAIL_PASSWORD)
    mail.select('inbox')
    status, messages = mail.search(None, 'UNSEEN')
    email_ids = messages[0].split()
    emails = []

    for eid in email_ids:
        _, msg_data = mail.fetch(eid, '(RFC822)')
        raw_email = msg_data[0][1]
        msg = email.message_from_bytes(raw_email)

        subject = msg.get('Subject', '')
        body = ''
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode(errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True).decode(errors='ignore')

        emails.append({'subject': subject, 'body': body})

    mail.logout()
    return emails

# === Run ingestion ===
if __name__ == '__main__':
    emails = fetch_unread_emails()

    for email_data in emails:
        subject = email_data['subject']
        body = email_data['body']
        text = subject + ' ' + body

        try:
            label = model.predict([text])[0]
        except Exception as e:
            label = None

        vt_info = enrich_with_virustotal(text)

        result = {
            'subject': subject,
            'label': int(label) if label is not None else None,
            'virustotal': vt_info
        }

        print(result)
