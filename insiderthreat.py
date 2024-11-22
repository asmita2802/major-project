import pandas as pd

def load_data():
    """Load data from CSV files into dataframes."""
    try:
        logon_df = pd.read_csv('logon.csv')
        device_df = pd.read_csv('device.csv')
        file_df = pd.read_csv('file.csv')
        email_df = pd.read_csv('email.csv')

        # Print column names to debug
        print("Logon DataFrame columns:", logon_df.columns)
        print("Device DataFrame columns:", device_df.columns)
        print("File DataFrame columns:", file_df.columns)
        print("Email DataFrame columns:", email_df.columns)

        return logon_df, device_df, file_df, email_df
    
    except Exception as e:
        raise RuntimeError(f"Error loading data: {e}")

def detect_threats(logon_df, device_df, file_df, email_df):
    """Detect potential insider threats based on various data sources."""

    threats = []

    # 1. Check for unusual logon times
    if 'username' in logon_df.columns:
        logon_df['username'] = logon_df['username'].fillna('unknown_user')  # Handle missing data
        logon_count = logon_df.groupby('username').size()
        for username, count in logon_count.items():
            if count > 10:  # Example threshold
                threats.append(f"User '{username}' has an unusually high number of logons.")
    else:
        threats.append("Column 'username' not found in logon_df")

    # 2. Check for access to sensitive files
    if 'filename' in file_df.columns and 'username' in file_df.columns:
        file_df['filename'] = file_df['filename'].fillna('')  # Handle missing data
        file_df['username'] = file_df['username'].fillna('unknown_user')  # Handle missing data
        sensitive_files = ['confidential.txt', 'secret_data.csv']
        sensitive_access = file_df[file_df['filename'].isin(sensitive_files)]
        for index, row in sensitive_access.iterrows():
            threats.append(f"File '{row['filename']}' accessed by user '{row['username']}'.")
    else:
        threats.append("Required columns not found in file_df")

    # 3. Check for abnormal device usage
    if 'device_id' in device_df.columns:
        device_df['device_id'] = device_df['device_id'].fillna('unknown_device')  # Handle missing data
        devices_used = device_df['device_id'].nunique()
        if devices_used > 5:  # Example threshold
            threats.append(f"Unusually high number of devices used: {devices_used}.")
    else:
        threats.append("Column 'device_id' not found in device_df")

    # 4. Check for suspicious email activity
    if 'subject' in email_df.columns and 'sender' in email_df.columns:
        email_df['subject'] = email_df['subject'].fillna('')  # Handle missing data
        email_df['sender'] = email_df['sender'].fillna('unknown_sender')  # Handle missing data
        suspicious_emails = email_df[email_df['subject'].str.contains('urgent', case=False)]
        for index, row in suspicious_emails.iterrows():
            threats.append(f"Suspicious email activity detected: '{row['subject']}' from '{row['sender']}'.")
    else:
        threats.append("Required columns not found in email_df")

    if not threats:
        threats.append("No threats detected.")

    return threats

# Example usage
if __name__ == "__main__":
    logon_df, device_df, file_df, email_df = load_data()
    threats = detect_threats(logon_df, device_df, file_df, email_df)
    for threat in threats:
        print(threat)
