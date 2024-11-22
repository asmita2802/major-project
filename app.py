from flask import Flask, render_template, request, jsonify
import pandas as pd
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define global variables for data
logon_df = None
device_df = None
file_df = None
email_df = None

def load_data():
    global logon_df, device_df, file_df, email_df
    try:
        logon_df = pd.read_csv('logon.csv')
        device_df = pd.read_csv('device.csv')
        file_df = pd.read_csv('file.csv')
        email_df = pd.read_csv('email.csv')
        logger.info("Data loaded successfully.")
    except Exception as e:
        logger.error(f"Error loading data: {e}")

def detect_threats():
    if logon_df is None or device_df is None or file_df is None or email_df is None:
        return ["Error loading data."]
    
    threats = []

    # Example detection logic
    try:
        logon_df['username'] = logon_df['username'].fillna('unknown_user')  # Handle missing data
        logon_count = logon_df.groupby('username').size()
        for username, count in logon_count.items():
            if count > 10:
                threats.append(f"User '{username}' has an unusually high number of logons.")
    except KeyError as e:
        threats.append(f"Column missing in logon.csv: {e}")

    sensitive_files = ['confidential.txt', 'secret_data.csv']
    try:
        file_df['filename'] = file_df['filename'].fillna('')  # Handle missing data
        file_df['username'] = file_df['username'].fillna('unknown_user')  # Handle missing data
        sensitive_access = file_df[file_df['filename'].isin(sensitive_files)]
        for index, row in sensitive_access.iterrows():
            threats.append(f"File '{row['filename']}' accessed by user '{row['username']}'.")
    except KeyError as e:
        threats.append(f"Column missing in file.csv: {e}")

    try:
        device_df['device_id'] = device_df['device_id'].fillna('unknown_device')  # Handle missing data
        devices_used = device_df['device_id'].nunique()
        if devices_used > 5:
            threats.append(f"Unusually high number of devices used: {devices_used}.")
    except KeyError as e:
        threats.append(f"Column missing in device.csv: {e}")

    try:
        email_df['subject'] = email_df['subject'].fillna('')  # Handle missing data
        email_df['sender'] = email_df['sender'].fillna('unknown_sender')  # Handle missing data
        suspicious_emails = email_df[email_df['subject'].str.contains('urgent', case=False)]
        for index, row in suspicious_emails.iterrows():
            threats.append(f"Suspicious email activity detected: '{row['subject']}' from '{row['sender']}'.")
    except KeyError as e:
        threats.append(f"Column missing in email.csv: {e}")

    if not threats:
        threats.append("No threats detected.")

    return threats

@app.route('/')
def index():
    load_data()  # Ensure data is loaded
    threats = detect_threats()
    return render_template('index.html', threats=threats)

@app.route('/threats')
def get_threats():
    load_data()  # Ensure data is loaded
    threats = detect_threats()
    return jsonify({'threats': threats})

if __name__ == "__main__":
    app.run(debug=True)