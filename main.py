import sqlite3       #used so that we can run and manage databases through sql commands insiide python
import hashlib       # hash function using sha256 etc.  for passwords
import datetime      # provide current date and time
import time          # give timestamps


# DATABASES


def get_db():
    return sqlite3.connect("security_system.db",
        check_same_thread=False
    )

db = get_db()
cur = db.cursor()        #cursor object used to execute sql commands

# USERS DATABASE
cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password TEXT,
    clearance INTEGER,
    locked INTEGER DEFAULT 0
)
""")

# CHINESE WALL MEMORY (keep info about which user accessed with company)
cur.execute("""
CREATE TABLE IF NOT EXISTS history(
    username TEXT, 
    company TEXT
)
""")

# SECURITY STATE  (keeps info about failed attemptsand locks account if needed, simple bruteforce prevention
cur.execute("""
CREATE TABLE IF NOT EXISTS security_state(
    username TEXT PRIMARY KEY,
    failed_attempts INTEGER DEFAULT 0,
    last_request REAL
)
""")

# AUDIT LOGS
cur.execute("""
CREATE TABLE IF NOT EXISTS logs(
    time TEXT,
    user TEXT,
    action TEXT,
    object TEXT,
    result TEXT
)
""")

db.commit()    #save all the changes made in database


# COI CLASSES
# consists of key :IT and values: Infosys, Wipro, HCL

COI_CLASSES = {
    "IT": ["TCS", "Infosys", "Wipro", "HCL"],
    "Banking": ["HDFC", "SBI", "Axis"],
    "Airlines": ["Delta", "United", "Emirates"],
    "Finance": ["CityBank", "MorganStanley", "UBS"]
}

#creates reverse mapping from companies to COI
DATASET_TO_COI = {
    company: coi
    for coi, companies in COI_CLASSES.items()
    for company in companies
}


# CLASSIFICATION LEVELS


CLASSIFICATION = {
    "Public": 1,
    "Internal": 2,
    "Confidential": 3,
    "Secret": 4,
    "TopSecret": 5
}


# OBJECT MODEL

# represent data object in system  that user can try to access
class Object:
    def __init__(self, name, company, level):
        self.name = name
        self.company = company
        self.coiclass = DATASET_TO_COI[company]
        self.level = CLASSIFICATION[level]


# stores all the data objects in the system in a dictonary for easy access
OBJECTS = {

    "1.1": Object("TCS_Public_Report", "TCS", "Public"),
    "1.2": Object("TCS_AI_Strategy", "TCS", "Secret"),
    "1.3": Object("Infosys_Cloud_Plan", "Infosys", "Confidential"),
    "1.4": Object("Wipro_Security_Model","Wipro","Confidential"),
    "1.5": Object("HCL_DataCenter","HCL","Internal"),

    "2.1": Object("HDFC_Loan_Data", "HDFC", "Internal"),
    "2.2": Object("HDFC_Audit_File", "HDFC", "TopSecret"),
    "2.3": Object("SBI_Risk_Report","SBI","Confidential"),
    "2.4": Object("Axis_Credit_Model","Axis","Secret"),

    "3.1": Object("Delta_Flight_Strategy", "Delta", "Confidential"),
    "3.2": Object("United_Pricing_Model","United","Internal"),
    "3.3": Object("Emirates_AI_Logistics","Emirates","Secret"),

    "4.1": Object("MorganStanley_Investment_Report", "MorganStanley", "Internal"),
    "4.2": Object("CityBank_Risk_Model", "CityBank", "Confidential"),
    "4.3": Object("MorganStanley_Market_AI", "MorganStanley", "Secret"),
    "4.4": Object("UBS_Wealth_Strategy", "UBS", "TopSecret")
}


# PASSWORD SECURITY


#converts a password into a safe hash before storing it into the database
def hash_pass(p):
    return hashlib.sha256(p.encode()).hexdigest()


#Add new users into the system
def add_user(username, password, clearance):
    cur.execute(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,0)",
        (username, hash_pass(password), clearance))
    cur.execute(
        "INSERT OR IGNORE INTO security_state(username) VALUES(?)",
        (username,))
    db.commit()


#check if user login attempt is valid
def authenticate(username, password):

    cur.execute("SELECT password,locked FROM users WHERE username=?",
                (username,))
    row = cur.fetchone()

    if not row:
        return False

    stored, locked = row

    if locked:
        print("🚫 ACCOUNT LOCKED")
        return False

    return stored == hash_pass(password)


# DATABASE HELPERS


#retrive user info needed for access check
def get_user(username):
    cur.execute("SELECT clearance,locked FROM users WHERE username=?",
                (username,))
    return cur.fetchone()


#retrive all companies user has accessed
def get_history(username):
    cur.execute("SELECT company FROM history WHERE username=?",
                (username,))
    return {r[0] for r in cur.fetchall()}


#record a new access in the Chinese wall memory
def add_history(username, company):
    cur.execute("INSERT INTO history VALUES (?,?)",
                (username, company))
    db.commit()

#lock a user account after too many failed login attempts
def lock_user(username):
    cur.execute("UPDATE users SET locked=1 WHERE username=?",
                (username,))
    db.commit()


# SECURITY MONITOR
# handles rate limiting and records login failure

class SecurityMonitor:

    @staticmethod
    def rate_limit(username):         #prevents too mny requests in a short period

        now = time.time()

        cur.execute(
            "SELECT last_request FROM security_state WHERE username=?",
            (username,))
        last = cur.fetchone()[0]

        if last and now - last < 1:
            print("⚠ Request Flood Detected")
            return False

        cur.execute(
            "UPDATE security_state SET last_request=? WHERE username=?",
            (now, username))
        db.commit()
        return True

    @staticmethod
    def record_failure(username):     #track failed login ttempts and lock acc after threshold

        cur.execute("""
        UPDATE security_state
        SET failed_attempts = failed_attempts + 1
        WHERE username=?""", (username,))
        db.commit()

        cur.execute("""
        SELECT failed_attempts FROM security_state
        WHERE username=?""", (username,))
        fails = cur.fetchone()[0]

        if fails >= 6:
            lock_user(username)
            return True

        return False


# POLICY ENGINE
#central place to inforce all policies

class PolicyEngine:

    @staticmethod
    def chinese_wall(username, obj):    # enforces chinese wall policies

        history = get_history(username)

        for accessed_company in history:
            if (
                DATASET_TO_COI[accessed_company] == obj.coiclass
                and accessed_company != obj.company
            ):
                return False
        return True

    @staticmethod
    def clearance(clearance, obj):      # enforce clearance level check
        return clearance >= obj.level




# AUDIT LOGGING
#records every action user taken into the system

def log_event(user, action, obj, result):

    cur.execute(
        "INSERT INTO logs VALUES (?,?,?,?,?)",
        (
            str(datetime.datetime.now()),
            user,
            action,
            obj,
            result
        )
    )

    db.commit()


# ACCESS HISTORY
#retrives acess history for specific users in redable format

def get_access_history(username):

    cur.execute("""
        SELECT time, action, object, result
        FROM logs
        WHERE user=?
        ORDER BY time DESC
    """, (username,))

    rows = cur.fetchall()

    history = []
    for r in rows:
        history.append({
            "time": r[0],
            "action": r[1],
            "object": r[2],
            "result": r[3]
        })

    return history


# ACCESS MANAGER
# manages all requests to access objects

class AccessManager:

    def request(self, username, obj_id, action):

        if not SecurityMonitor.rate_limit(username):
            return

        user = get_user(username)
        clearance, locked = user

        if locked:
            print("🚫 ACCOUNT LOCKED")
            return

        obj = OBJECTS[obj_id]

        if not PolicyEngine.chinese_wall(username, obj):
            print("❌ COI VIOLATION")
            SecurityMonitor.record_failure(username)
            log_event(username, action, obj.name, "DENIED")
            return

        if not PolicyEngine.clearance(clearance, obj):
            print(
                f"❌ INSUFFICIENT CLEARANCE "
                f"(Required:{obj.level} | Yours:{clearance})"
            )
            SecurityMonitor.record_failure(username)
            log_event(username, action, obj.name, "DENIED")
            return

        add_history(username, obj.company)
        log_event(username, action, obj.name, "ALLOWED")

        print(f"✅ ACCESS GRANTED → {obj.name}")


# INITIAL USERS


add_user("karnika","1234",3)
add_user("vansh","1234",4)
add_user("ram","1234",4)

manager = AccessManager()


# UI


def show_objects():

    print("\n===== OBJECT HIERARCHY =====")

    grouped = {}

    for fid, obj in OBJECTS.items():
        grouped.setdefault(obj.coiclass, []).append((fid, obj))

    for coi, items in grouped.items():
        print(f"\nCOI: {coi}")

        for fid, obj in items:
            print(
                f"{fid} | {obj.name} | "
                f"Company:{obj.company} | "
                f"Clearance Needed:{obj.level}"
            )


# SESSION


def user_session(username):

    user = get_user(username)
    user_clearance = user[0]

    print("\n===== USER INFO =====")
    print(f"User: {username}")
    print(f"Clearance Level: {user_clearance}")
    print("=====================\n")

    while True:

        print("\n1.View Objects")
        print("2.Read")
        print("3.Write")
        print("4.View Access History")
        print("5.Logout")

        ch = input("Choice: ")

        if ch == "1":
            show_objects()

        elif ch == "2":
            fid = input("Object ID: ")
            if fid in OBJECTS:
                manager.request(username, fid, "READ")

        elif ch == "3":
            fid = input("Object ID: ")
            if fid in OBJECTS:
                manager.request(username, fid, "WRITE")

        elif ch == "4":

            history = get_access_history(username)

            print("\n===== ACCESS HISTORY =====")

            if not history:
                print("No activity yet")

            for h in history:
                print(
                    f"{h['time']} | "
                    f"{h['action']} | "
                    f"{h['object']} | "
                    f"{h['result']}"
                )

        else:
            print("Logged out")
            break


# LOGIN SYSTEM


def login_system():

    while True:

        print("\n===== LOGIN =====")

        username = input("Username: ")
        password = input("Password: ")

        if not authenticate(username, password):
            print("Authentication Failed")
            continue

        user = get_user(username)

        if user and user[1]:
            print("🚫 Account Locked")
            continue

        user_session(username)


if __name__ == "__main__":
    login_system()