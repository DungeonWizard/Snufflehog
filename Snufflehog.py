from alive_progress import alive_bar
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

def count_files(folder_path):
    total = 0
    for _, _, files in os.walk(folder_path):
        total += len(files)
    return total

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
                passwordRegex = "[A-Za-z0-9_!@#$%^&*\-+=.?]+"
                passwordPatterns = \
                    re.compile(r"--acerpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--acerpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--acerpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--adminpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--adminpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--adminpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--admpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--admpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--admpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--adpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--adpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--adpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--amazonpass "+passwordRegex).findall(line) + \
                    re.compile(r"--amazonpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--amazonpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--amazonpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--amazonpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--amazonpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--antiviruspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--antiviruspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--antiviruspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--apachepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--apachepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--apachepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--asuspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--asuspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--asuspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--aterapassword "+passwordRegex).findall(line) + \
                    re.compile(r"--aterapassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--aterapassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--avpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--avpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--avpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--awspass "+passwordRegex).findall(line) + \
                    re.compile(r"--awspass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--awspass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--awspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--awspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--awspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--axispassword "+passwordRegex).findall(line) + \
                    re.compile(r"--axispassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--axispassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--azurepass "+passwordRegex).findall(line) + \
                    re.compile(r"--azurepass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--azurepass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--azurepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--azurepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--azurepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--badgepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--badgepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--badgepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--bankpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--bankpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--bankpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--bannerldappassword "+passwordRegex).findall(line) + \
                    re.compile(r"--bannerldappassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--bannerldappassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--bannerpass "+passwordRegex).findall(line) + \
                    re.compile(r"--bannerpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--bannerpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--bannerpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--bannerpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--bannerpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--camerapassword "+passwordRegex).findall(line) + \
                    re.compile(r"--camerapassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--camerapassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--campassword "+passwordRegex).findall(line) + \
                    re.compile(r"--campassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--campassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--canvaspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--canvaspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--canvaspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--cardpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--cardpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--cardpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--cashnetpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--cashnetpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--cashnetpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--cashpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--cashpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--cashpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--classpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--classpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--classpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--cloudpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--cloudpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--cloudpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--compassword "+passwordRegex).findall(line) + \
                    re.compile(r"--compassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--compassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--computepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--computepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--computepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--computerpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--computerpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--computerpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--configpass "+passwordRegex).findall(line) + \
                    re.compile(r"--configpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--configpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--configpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--configpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--configpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--coursepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--coursepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--coursepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--creditpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--creditpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--creditpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--crmpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--crmpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--crmpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--databasepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--databasepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--databasepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--dbpass "+passwordRegex).findall(line) + \
                    re.compile(r"--dbpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--dbpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--dbpasswd "+passwordRegex).findall(line) + \
                    re.compile(r"--dbpasswd \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--dbpasswd \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--dbpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--dbpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--dbpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--debianpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--debianpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--debianpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--defaultpass "+passwordRegex).findall(line) + \
                    re.compile(r"--defaultpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--defaultpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--defaultpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--defaultpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--defaultpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--defenderpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--defenderpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--defenderpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--diagpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--diagpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--diagpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ellucianpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--ellucianpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ellucianpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--erppassword "+passwordRegex).findall(line) + \
                    re.compile(r"--erppassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--erppassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--genetecpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--genetecpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--genetecpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--githubpass "+passwordRegex).findall(line) + \
                    re.compile(r"--githubpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--githubpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--githubpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--githubpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--githubpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--gitlabpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--gitlabpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--gitlabpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--gitpass "+passwordRegex).findall(line) + \
                    re.compile(r"--gitpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--gitpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--gitpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--gitpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--gitpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--googlepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--googlepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--googlepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--guestpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--guestpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--guestpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ldappass "+passwordRegex).findall(line) + \
                    re.compile(r"--ldappass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ldappass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ldappassword "+passwordRegex).findall(line) + \
                    re.compile(r"--ldappassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ldappassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--linuxpass "+passwordRegex).findall(line) + \
                    re.compile(r"--linuxpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--linuxpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--linuxpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--linuxpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--linuxpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--localpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--localpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--localpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--mailpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--mailpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--mailpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--mariadbpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--mariadbpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--mariadbpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--masterpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--masterpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--masterpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--microsoftpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--microsoftpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--microsoftpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--moneypassword "+passwordRegex).findall(line) + \
                    re.compile(r"--moneypassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--moneypassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--moodlepass "+passwordRegex).findall(line) + \
                    re.compile(r"--moodlepass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--moodlepass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--moodlepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--moodlepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--moodlepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--netpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--netpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--netpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--oraclepass "+passwordRegex).findall(line) + \
                    re.compile(r"--oraclepass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--oraclepass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--oraclepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--oraclepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--oraclepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--orapass "+passwordRegex).findall(line) + \
                    re.compile(r"--orapass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--orapass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--orapassword "+passwordRegex).findall(line) + \
                    re.compile(r"--orapassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--orapassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--owapassword "+passwordRegex).findall(line) + \
                    re.compile(r"--owapassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--owapassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--pass "+passwordRegex).findall(line) + \
                    re.compile(r"--pass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--pass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--passwd "+passwordRegex).findall(line) + \
                    re.compile(r"--passwd \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--passwd \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--password "+passwordRegex).findall(line) + \
                    re.compile(r"--password \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--password \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--payrollpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--payrollpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--payrollpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--plexpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--plexpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--plexpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--pluspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--pluspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--pluspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--printerpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--printerpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--printerpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--printpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--printpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--printpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--prodpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--prodpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--prodpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--randompassword "+passwordRegex).findall(line) + \
                    re.compile(r"--randompassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--randompassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--routerpass "+passwordRegex).findall(line) + \
                    re.compile(r"--routerpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--routerpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--routerpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--routerpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--routerpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--saaspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--saaspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--saaspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--salespassword "+passwordRegex).findall(line) + \
                    re.compile(r"--salespassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--salespassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--samlpass "+passwordRegex).findall(line) + \
                    re.compile(r"--samlpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--samlpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--samlpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--samlpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--samlpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--secretpass "+passwordRegex).findall(line) + \
                    re.compile(r"--secretpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--secretpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--secretpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--secretpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--secretpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--serverpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--serverpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--serverpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--sessionpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--sessionpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--sessionpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--shellpass "+passwordRegex).findall(line) + \
                    re.compile(r"--shellpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--shellpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--shellpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--shellpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--shellpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--signpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--signpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--signpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--slatepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--slatepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--slatepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--smbpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--smbpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--smbpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--smtppassword "+passwordRegex).findall(line) + \
                    re.compile(r"--smtppassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--smtppassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--solarpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--solarpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--solarpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--solsticepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--solsticepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--solsticepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--squidpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--squidpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--squidpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--starpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--starpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--starpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--sudopassword "+passwordRegex).findall(line) + \
                    re.compile(r"--sudopassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--sudopassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--tableaupass "+passwordRegex).findall(line) + \
                    re.compile(r"--tableaupass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--tableaupass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--tableaupassword "+passwordRegex).findall(line) + \
                    re.compile(r"--tableaupassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--tableaupassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--temporarypassword "+passwordRegex).findall(line) + \
                    re.compile(r"--temporarypassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--temporarypassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--testpass "+passwordRegex).findall(line) + \
                    re.compile(r"--testpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--testpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--testpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--testpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--testpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--tomcatpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--tomcatpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--tomcatpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ubiquitipass "+passwordRegex).findall(line) + \
                    re.compile(r"--ubiquitipass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ubiquitipass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ubiquitipassword "+passwordRegex).findall(line) + \
                    re.compile(r"--ubiquitipassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ubiquitipassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ubuntupass "+passwordRegex).findall(line) + \
                    re.compile(r"--ubuntupass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ubuntupass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--ubuntupassword "+passwordRegex).findall(line) + \
                    re.compile(r"--ubuntupassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--ubuntupassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--unifipass "+passwordRegex).findall(line) + \
                    re.compile(r"--unifipass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--unifipass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--unifipassword "+passwordRegex).findall(line) + \
                    re.compile(r"--unifipassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--unifipassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--vcenterpass "+passwordRegex).findall(line) + \
                    re.compile(r"--vcenterpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--vcenterpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--vcenterpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--vcenterpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--vcenterpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--vmpass "+passwordRegex).findall(line) + \
                    re.compile(r"--vmpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--vmpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--vmpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--vmpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--vmpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--webpass "+passwordRegex).findall(line) + \
                    re.compile(r"--webpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--webpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--webpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--webpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--webpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--windowspass "+passwordRegex).findall(line) + \
                    re.compile(r"--windowspass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--windowspass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--windowspassword "+passwordRegex).findall(line) + \
                    re.compile(r"--windowspassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--windowspassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--winpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--winpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--winpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--workerpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--workerpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--workerpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--workpass "+passwordRegex).findall(line) + \
                    re.compile(r"--workpass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--workpass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--workpassword "+passwordRegex).findall(line) + \
                    re.compile(r"--workpassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--workpassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--zonepass "+passwordRegex).findall(line) + \
                    re.compile(r"--zonepass \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--zonepass \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"--zonepassword "+passwordRegex).findall(line) + \
                    re.compile(r"--zonepassword \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"--zonepassword \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"pass = "+passwordRegex).findall(line) + \
                    re.compile(r"pass = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"pass = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"pass="+passwordRegex).findall(line) + \
                    re.compile(r"pass=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"pass=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"Pass = "+passwordRegex).findall(line) + \
                    re.compile(r"Pass = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"Pass = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"Pass="+passwordRegex).findall(line) + \
                    re.compile(r"Pass=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"Pass=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"PASS = "+passwordRegex).findall(line) + \
                    re.compile(r"PASS = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"PASS = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"PASS="+passwordRegex).findall(line) + \
                    re.compile(r"PASS=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"PASS=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"passwd = "+passwordRegex).findall(line) + \
                    re.compile(r"passwd = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"passwd = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"passwd="+passwordRegex).findall(line) + \
                    re.compile(r"passwd=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"passwd=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"Passwd = "+passwordRegex).findall(line) + \
                    re.compile(r"Passwd = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"Passwd = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"Passwd="+passwordRegex).findall(line) + \
                    re.compile(r"Passwd=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"Passwd=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"PASSWD = "+passwordRegex).findall(line) + \
                    re.compile(r"PASSWD = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"PASSWD = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"PASSWD="+passwordRegex).findall(line) + \
                    re.compile(r"PASSWD=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"PASSWD=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"password = "+passwordRegex).findall(line) + \
                    re.compile(r"password = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"password = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"password="+passwordRegex).findall(line) + \
                    re.compile(r"password=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"password=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"Password = "+passwordRegex).findall(line) + \
                    re.compile(r"Password = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"Password = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"Password="+passwordRegex).findall(line) + \
                    re.compile(r"Password=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"Password=\""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"PASSWORD = "+passwordRegex).findall(line) + \
                    re.compile(r"PASSWORD = \'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"PASSWORD = \""+passwordRegex+"\"").findall(line) + \
                    re.compile(r"PASSWORD="+passwordRegex).findall(line) + \
                    re.compile(r"PASSWORD=\'"+passwordRegex+"\'").findall(line) + \
                    re.compile(r"PASSWORD=\""+passwordRegex+"\"").findall(line)
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
    total_files = count_files(folder_path)
    with alive_bar(total_files,title='Scanning',spinner='dots_waves2',enrich_print=False) as bar:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                numberScanned += 1
                if file in sensitiveFiles:
                    foundFiles.append(outputFile(root, file, file.split(".")[-1]))
                for extension in sensitiveExtensions:
                    if file.lower().endswith(extension) and file not in exceptions:
                        foundFiles.append(outputFile(root, file, extension))
                bar.text(f"{file}")
                bar()

    return (foundFiles, numberScanned)

# Comment out any that you don't care about.
sensitiveExtensions = [
    # a
    ".ansible",
    ".asc",
    ".auto.tfvars",
    ".aws",
    ".awscredentials",
    ".azure",
    # b
    ".backup",
    ".bak",
    ".bash_history",
    ".boto",
    ".buildkite",
    ".bzr",
    # c
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
    # d
    ".db",
    ".db3",
    ".der",
    ".dockercfg",
    ".dockerconfigjson",
    ".dockerignore",
    # e
    ".entitlements",
    ".env",
    # f
    ".ffs_db",
    # g
    ".gcloud",
    ".git",
    ".github",
    ".gitlab-ci",
    ".gpg",
    ".gsutil",
    # h
    ".h",
    ".heroku",
    ".hg",
    ".history",
    ".htaccess",
    ".htpasswd",
    # i
    ".id_dsa",
    ".id_ecdsa",
    ".id_ed25519",
    ".id_rsa",
    ".ini",
    ".inventory",
    # j
    ".java",
    ".jenkins",
    ".jks",
    ".js",
    ".json",
    # k
    ".key",
    ".keychain",
    ".keys",
    ".keystore",
    ".kube",
    ".kubeconfig",
    # l
    ".ldb",
    ".ldf",
    ".log",
    # m
    ".md",
    ".mdf",
    ".mobileprovision",
    ".my.cnf",
    # n
    ".netlify",
    ".netrc",
    ".nomad",
    ".npmrc",
    # o
    ".old",
    ".orig",
    ".ovpn",
    # p
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
    # r
    ".realm",
    # s
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
    # t
    ".teamcity",
    ".terraform",
    ".tfstate",
    ".tfstate.backup",
    ".tfvars",
    ".tmp",
    ".toml",
    ".travis",
    ".txt",
    # v
    ".vault",
    # w
    ".wal",
    # x
    ".xcuserstate",
    ".xml",
    # y
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
    "C:/Users/Public/Desktop",
    "C:/Users/Public/Documents",
    "C:/Users/Public/Downloads",
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