import os

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

findings = []

def outputFile(root, file, extension):
    filePath = os.path.join(root, file)
    filePathFinal = filePath.replace(file, f"{bcolors.FAIL}"+file+f"{bcolors.ENDC}").replace(extension, f"{bcolors.RED}"+extension+f"{bcolors.ENDC}")
    filePathFinal = filePathFinal.replace(directory, "").replace("\\","/")
    print(f" 📄 {bcolors.RED}" + filePathFinal + f"{bcolors.ENDC}")
    # Check file contents for more specific findings.
    with open(filePath, "r", encoding="utf-8", errors="ignore") as f:
        contents = f.read()
        if "-----BEGIN CERTIFICATE-----" in contents:
            findings.append(f"   ⚠️ {bcolors.FAIL}Certificate found: {bcolors.ENDC}{bcolors.RED}"+filePath+f"{bcolors.ENDC}")
        if "-----BEGIN PRIVATE KEY-----" in contents or "-----BEGIN RSA PRIVATE KEY-----" in contents:
            findings.append(f"   ⚠️ {bcolors.FAIL}Private key found: {bcolors.ENDC}{bcolors.RED}"+filePath+f"{bcolors.ENDC}")
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
    ".vault",
    ".wal",
    ".xcuserstate",
    ".yarnrc",
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