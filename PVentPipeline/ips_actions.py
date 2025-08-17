def quarantine_message(msg_id, conn):
    '''Move the message to quarantine (set flag in DB).'''
    with conn.cursor() as cursor:
        cursor.execute("UPDATE messages SET quarantined = TRUE WHERE id = %s", (msg_id,))
    conn.commit()

def notify_admin(msg_id, conn):
    '''Send a notification to the admin about the flagged message (placeholder).'''
    print(f"Admin notified about message {msg_id}.")

def block_sender(sender, conn):
    '''Add the sender to a blocklist table (placeholder).'''
    with conn.cursor() as cursor:
        cursor.execute("INSERT INTO blocklist (sender) VALUES (%s) ON CONFLICT DO NOTHING", (sender,))
    conn.commit()

def escalate_incident(msg_id, conn):
    '''Escalate the incident for further investigation (placeholder).'''
    print(f"Incident escalated for message {msg_id}.")