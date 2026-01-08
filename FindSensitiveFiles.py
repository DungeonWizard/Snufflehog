import os
import re

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    BACKGROUND_MAGENTA = '\033[105m'
    BACKGROUND_WHITE = '\033[47m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    ORANGE = '\033[38;5;208m'

os.system("color") # Comment out on Linux

findings = []

def outputFile(root, file, extension):
    filePath = os.path.join(root, file)
    filePathFinal = filePath.replace(file, f"{bcolors.FAIL}"+file+f"{bcolors.ENDC}").replace(extension, f"{bcolors.RED}"+extension+f"{bcolors.ENDC}")
    filePathFinal = filePathFinal.replace(directory, "").replace("\\","/")
    # print(f" 📄 {bcolors.RED}" + filePathFinal + f"{bcolors.ENDC}")
    # Check file contents for more specific findings.
    try:
        with open(filePath, "r", encoding="utf-8", errors="ignore") as f:
            lineCounter = 0
            for line in f:
                # Certificates (this leads to a lot of junk detections, so I've commented it by default; uncomment it if you're looking for stray certificates lying around)
                if "-----BEGIN CERTIFICATE-----" in line:
                    # findings.append(f"   ⚠️ {bcolors.FAIL}Certificate found ["+str(lineCounter)+f"]: {bcolors.ENDC}{bcolors.RED}"+filePath+f"{bcolors.ENDC}")
                    pass
                # Private keys
                if "-----BEGIN PRIVATE KEY-----" in line or "-----BEGIN RSA PRIVATE KEY-----" in line:
                    findings.append(f"   ⚠️ {bcolors.FAIL}Private key found ["+str(lineCounter)+f"]: {bcolors.ENDC}{bcolors.RED}"+filePath+f"{bcolors.ENDC}")
                # Passwords
                passwordPatterns = \
                    re.compile(r"passwd = [A-Za-z0-9_]+").findall(line) + \
                    re.compile(r"passwd = \'[A-Za-z0-9_]+\'").findall(line) + \
                    re.compile(r"passwd = \"[A-Za-z0-9_]+\"").findall(line) + \
                    re.compile(r"passwd=[A-Za-z0-9_]+").findall(line) + \
                    re.compile(r"passwd=\'[A-Za-z0-9_]+\'").findall(line) + \
                    re.compile(r"passwd=\"[A-Za-z0-9_]+\"").findall(line) + \
                    re.compile(r"password = [A-Za-z0-9_]+").findall(line) + \
                    re.compile(r"password = \'[A-Za-z0-9_]+\'").findall(line) + \
                    re.compile(r"password = \"[A-Za-z0-9_]+\"").findall(line) + \
                    re.compile(r"password=[A-Za-z0-9_]+").findall(line) + \
                    re.compile(r"password=\'[A-Za-z0-9_]+\'").findall(line) + \
                    re.compile(r"password=\"[A-Za-z0-9_]+\"").findall(line) + \
                    re.compile(r"Password = [A-Za-z0-9_]+").findall(line) + \
                    re.compile(r"Password = \'[A-Za-z0-9_]+\'").findall(line) + \
                    re.compile(r"Password = \"[A-Za-z0-9_]+\"").findall(line) + \
                    re.compile(r"Password=[A-Za-z0-9_]+").findall(line) + \
                    re.compile(r"Password=\'[A-Za-z0-9_]+\'").findall(line) + \
                    re.compile(r"Password=\"[A-Za-z0-9_]+\"").findall(line)
                for m in passwordPatterns:
                    findings.append(f"   ⚠️ {bcolors.FAIL}Password found ["+str(lineCounter)+f"]: {bcolors.ENDC}{bcolors.RED}"+filePath+f"{bcolors.ENDC} ({bcolors.WARNING}"+m+f"{bcolors.ENDC})")
                # GitHub Personal Access Tokens (PATs)
                PATPattern = re.compile(r"\bgithub_pat_[A-Za-z0-9_]+\b")
                for m in PATPattern.findall(line):
                    findings.append(f"   ⚠️ {bcolors.FAIL}GitHub PAT found ["+str(lineCounter)+f"]: {bcolors.ENDC}{bcolors.RED}"+filePath+f"{bcolors.ENDC} ({bcolors.WARNING}"+m+f"{bcolors.ENDC})")
                lineCounter+=1
    except Exception as e: pass
    # Return the shortened file path.
    return filePath

def scan(folder_path):
    numberScanned = 0
    foundFiles = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            numberScanned += 1
            if file in sensitiveFiles:
                foundFiles.append(outputFile(root, file, file.split(".")[-1]))
            for extension in sensitiveExtensions:
                if file.lower().endswith(extension) and file not in exceptions:
                    foundFiles.append(outputFile(root, file, extension))

    return (foundFiles, numberScanned)

# Comment out any that you don't care about.
sensitiveExtensions = [
    ".ansible",
    ".asc",
    ".auto.tfvars",
    ".aws",
    ".awscredentials",
    ".azure",
    ".backup",
    ".bak",
    ".bash_history",
    ".boto",
    ".buildkite",
    ".bzr",
    ".cache",
    ".cer",
    ".cert",
    ".cfg",
    ".circleci",
    ".conf",
    ".config",
    ".consul",
    ".cpp",
    ".credentials",
    ".crt",
    ".csr",
    ".db",
    ".db3",
    ".der",
    ".dockercfg",
    ".dockerconfigjson",
    ".dockerignore",
    ".entitlements",
    ".env",
    ".ffs_db",
    ".gcloud",
    ".git",
    ".github",
    ".gitlab-ci",
    ".gpg",
    ".gsutil",
    ".heroku",
    ".h",
    ".hg",
    ".history",
    ".htaccess",
    ".htpasswd",
    ".id_dsa",
    ".id_ecdsa",
    ".id_ed25519",
    ".id_rsa",
    ".ini",
    ".inventory",
    ".jenkins",
    ".json",
    ".key",
    ".keychain",
    ".keys",
    ".keystore",
    ".kube",
    ".jks",
    ".kubeconfig",
    ".ldb",
    ".ldf",
    ".log",
    ".mdf",
    ".mobileprovision",
    ".my.cnf",
    ".netlify",
    ".netrc",
    ".nomad",
    ".npmrc",
    ".old",
    ".orig",
    ".ovpn",
    ".p12",
    ".passwd",
    ".pem",
    ".pfx",
    ".pgp",
    ".pgpass",
    ".php",
    ".pip.conf",
    ".plist",
    ".poetry",
    ".properties",
    ".pypirc",
    ".realm",
    ".s3cfg",
    ".save",
    ".seckey",
    ".secrets",
    ".settings",
    ".shadow",
    ".SharedSecrets",
    ".sig",
    ".spkac",
    ".sql",
    ".sqlite",
    ".sqlite3",
    ".ssh",
    ".sshconfig",
    ".svn",
    ".swap",
    ".swp",
    ".teamcity",
    ".terraform",
    ".tfstate",
    ".tfstate.backup",
    ".tfvars",
    ".tmp",
    ".travis",
    ".txt",
    ".vault",
    ".wal",
    ".xcuserstate",
    ".yaml",
    ".yarnrc",
    ".yml",
]
sensitiveFiles = [
    ".env.dev",
    ".env.local",
    ".env.prod",
    ".env.production",
    "apikey",
    "backup",
    "config",
    "credentials",
    "database",
    "dump",
    "PASSWORD.txt",
    "PASSWORDS.txt",
    "password.txt",
    "passwords.txt",
    "private",
    "secret",
    "secret.txt",
    "secrets",
    "secrets.txt",
    "seed",
    "settings",
    "token",
    "wallet",
]
exceptions = [
    "desktop.ini",
    "Thumbs.db",
]
directories = [
    "C:/Users/Public",
]
for directory in directories:
    print(f"📁 {bcolors.WARNING}"+directory+f"{bcolors.ENDC}")    
    files, numberScanned = scan(directory)
    if not files:
        print(f"  ✅ {bcolors.OKGREEN}Nothing found.{bcolors.ENDC} ({bcolors.WARNING}{numberScanned:,} files checked{bcolors.ENDC})")
    else:
        print(f"  ☣️ {bcolors.OKGREEN}Some files found.{bcolors.ENDC} ({bcolors.WARNING}{numberScanned:,} files checked{bcolors.ENDC})")
    if findings:
        for finding in findings:
            print(finding)