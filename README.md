# Brewer-Nash-Security-System
A dynamic access control simulator implementing the Chinese Wall (BREWER-NASH) security model.

 
This system is designed to prevent conflicts of interest (COI), enforce clearance levels, monitor user activity, and maintain detailed audit logs for accountability.

---

## 🌟 Features

- **Chinese Wall Policy Enforcement:**  
  Prevents users from accessing conflicting data within the same COI (e.g., IT, Banking, Airlines, Finance).

- **Clearance Levels:**  
  Each object has a classification: Public → TopSecret (1–5).  
  Users can only access objects at or below their clearance level.

- **Security Monitor & Anti-Attack Measures:**  
  - **Rate Limiting:** Stops request flooding (too many requests per second).  
  - **Failed Attempt Tracking:** Locks a user account after 6 failed attempts to prevent brute-force attacks.

- **Audit Logging:**  
  Records all actions with timestamp, username, action (READ/WRITE), object, and result (ALLOWED/DENIED).  
  Enables forensic analysis and accountability.

- **Interactive User Session:**  
  Users can view objects, read/write files, and check their access history.

---

## 🛠 Modules & Libraries Used

- **SQLite3:** Persistent storage for users, access history, and audit logs.  
- **Hashlib:** Secure password hashing using SHA-256.  
- **Datetime & Time:** Timestamping for logging and rate-limiting.  

---

## 🧭 How It Works (Methodology)

1. **User Authentication:**  
   Users log in using a username and password. Passwords are securely hashed before storage.

2. **Policy Enforcement:**  
   The system checks:  
   - **Chinese Wall Policy** → prevents accessing data from conflicting companies within the same COI.  
   - **Clearance Levels** → ensures users can only access objects they are authorized for.  

3. **Security Monitor:**  
   - **Rate Limiting:** Prevents users from sending too many requests too quickly.  
   - **Failed Attempts Tracking:** Locks the account after 6 failed attempts.

4. **Access Manager:**  
   Processes READ and WRITE requests according to policies.

5. **History & Logging:**  
   Stores accessed companies and logs every action with full details for monitoring and auditing.

---

## 📁 Object & COI Structure

- Objects belong to different **companies** and **COIs**.  
- Example COIs:  
  - **IT:** TCS, Infosys, Wipro, HCL  
  - **Banking:** HDFC, SBI, Axis  
  - **Airlines:** Delta, United, Emirates  
  - **Finance:** CityBank, MorganStanley, UBS  

- Objects have classification levels:  
  - Public (1) → Internal (2) → Confidential (3) → Secret (4) → TopSecret (5)

---

## 🔧 Installation

1. Clone the repository:

```bash
git clone https://github.com/karnikaagarwal/Brewer-Nash-Security-System.git
