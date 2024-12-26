from email_fetch import fetch_emails
from phishing_detector import detect_phishing

def main():
    print("Starting the email processing and phishing detection...")
    try:
        fetch_emails()
        detect_phishing()
    except Exception as e:
        print(f"An error occurred during execution: {e}")
    finally:
        print("Execution completed.")

if __name__ == "__main__":
    main()
