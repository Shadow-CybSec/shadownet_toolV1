import sys
import os
from colorama import Fore, Back, Style
import time
import socket
import hashlib


def colreset():
 print(Style.RESET_ALL)

def menu():
 os.system('clear')
 print(Fore.BLUE + """
  ____  _               _               _   _      _   
 / ___|| |__   __ _  __| | _____      _| \ | | ___| |_ 
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /  \| |/ _ \ __|
  ___) | | | | (_| | (_| | (_) \ V  V /| |\  |  __/ |_ 
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| \_|\___|\__|
                                                       


""")
 print(Fore.RED + "\nRun as Sudo - Popping shells since '07 - Welcome Back Shadow\n\n")
 colreset()

 mainmen = input(Fore.RED + """
	1: NMap Scan
	2: DNSScan
	3: SSlScan
	4: Reverse Lookup
	5: Wordpress Scan
	6: CMS Detect
	7: DIR Brute
	8: Hash Generator
	9: Quick Math
	10: Search ExploitDB
	11: Update DB
	12: Print Version
	13: Exit ShadowNet""" + Fore.GREEN + "\nEnter Choice: ")
 colreset()
 if mainmen == 1:
  nmap()
  return
 elif mainmen == 2:
  dns()
  return
 elif mainmen == 3:
  ssl()
  return
 elif mainmen == 4:
  revlook()
  return
 elif mainmen == 5:
  wpscan()
  return
 elif mainmen == 6:
  cmsdet()
  return
 elif mainmen == 7:
  dirbrute()
  return
 elif mainmen == 8:
  hashgen()
  return
 elif mainmen == 9:
  quickmath()
  return
 elif mainmen == 10:
  exploitdb()
  return
 elif mainmen == 11:
  update()
  return
 elif mainmen == 12:
  version()
  return
 elif mainmen == 13:
  exit()
 else:
  exit()

def nmap():
 os.system('clear')
 print(Fore.RED + """
 /$$   /$$                                  
| $$$ | $$                                  
| $$$$| $$ /$$$$$$/$$$$   /$$$$$$   /$$$$$$ 
| $$ $$ $$| $$_  $$_  $$ |____  $$ /$$__  $$
| $$  $$$$| $$ \ $$ \ $$  /$$$$$$$| $$  \ $$
| $$\  $$$| $$ | $$ | $$ /$$__  $$| $$  | $$
| $$ \  $$| $$ | $$ | $$|  $$$$$$$| $$$$$$$/
|__/  \__/|__/ |__/ |__/ \_______/| $$____/ 
                                  | $$      
                                  | $$      
                                  |__/      
\n""")
 colreset()
 nmaptar = raw_input(Fore.MAGENTA + "\nEnter Target: ")
 nmapout = raw_input("\nEnter Output filename: ")
 nmport = raw_input("\nEnter Port/Range - Blank for auto: ")
 colreset()
 nmapopt = input(Fore.RED + """\n
 1. Quick Scan
 2. Full Scan
 Enter Scan Type: """)

 if nmapopt == 1 or "1":
  os.system('nmap ' + nmaptar + ' -oG ' + nmapout)
  raw_input(Fore.MAGENTA + '\nPress enter to return to menu....')
  return menu() 
 elif nmapopt == 2 or "2":
  os.system('nmap --script="*" -A ' + nmaptar + ' -oG ' + nmapout) 
  raw_input(Fore.MAGENTA + '\nPress enter to return to menu....')
  return menu()
 else:
  return nmap()

def dns():
 os.system('clear')
 print(Fore.GREEN + """
                                          
 ____  _____ _____ _____                 
|    \|   | |   __| __  |___ ___ ___ ___ 
|  |  | | | |__   |    -| -_|  _| . |   |
|____/|_|___|_____|__|__|___|___|___|_|_|
                                         

""")
 colreset()
 dnsserv = raw_input(Fore.MAGENTA + "\nEnter DNS Server Address: ")
 dnsout = raw_input("\nEnter output filename: ")
 colreset()
 os.system("dnsrecon --xml " + dnsout + " -d " + dnsserv)
  
 raw_input("\nPress enter to return to menu....")
 return menu()

def ssl():
 print(Fore.RED + """
                                      
 _____ _____ __    _____             
|   __|   __|  |  |   __|___ ___ ___ 
|__   |__   |  |__|__   |  _| .'|   |
|_____|_____|_____|_____|___|__,|_|_|
                                     
\n\n
 """)
 sslhost = raw_input(Fore.GREEN + "\nEnter HTTPS Server: ")
 colreset()
 os.system('sslscan ' + sslhost)
 raw_input(Fore.MAGENTA + '\nPress enter to return to menu....')
 return menu()
 
def revlook():
 colreset()
 os.system('clear')
 print("""
                                                          
 _____                         __            _           
| __  |___ _ _ ___ ___ ___ ___|  |   ___ ___| |_ _ _ ___ 
|    -| -_| | | -_|  _|_ -| -_|  |__| . | . | '_| | | . |
|__|__|___|\_/|___|_| |___|___|_____|___|___|_,_|___|  _|
                                                    |_|  


 """)
 host = raw_input(Fore.MAGENTA + "Enter Hostname: ")
 colreset()
 revdns = socket.gethostbyaddr(host)
 print(revdns)
 colreset()
 raw_input(Fore.MAGENTA + '\nPress enter to return to menu....')
 return menu()
 
def wpscan():
 os.system('clear')
 print(Fore.MAGENTA + """
  __    __              _                         
/ / /\ \ \___  _ __ __| |_ __  _ __ ___  ___ ___ 
\ \/  \/ / _ \| '__/ _` | '_ \| '__/ _ \/ __/ __|
 \  /\  / (_) | | | (_| | |_) | | |  __/\__ \__ \
  \/  \/ \___/|_|  \__,_| .__/|_|  \___||___/___/
                        |_|                      

""")
 
 wphost = raw_input(Fore.GREEN + "\nEnter Wordpress Domain: ")
 wpout = raw_input("\nEnter Output Filename: ")
 colreset()
 os.system('wpscan --rua -e ap, vp, u --url ' + wphost + ' -o ' + wpout)
 time.sleep(60)
 raw_input(Fore.RED + "\nPress enter to return to menu....")
 return menu()
 
def exploitdb():
 colreset()
 os.system('clear')
 print("""                                                                                   
 
     ______           __      _ __  ____  ____ 
    / ____/  ______  / /___  (_) /_/ __ \/ __ )
   / __/ | |/_/ __ \/ / __ \/ / __/ / / / __  |
  / /____>  </ /_/ / / /_/ / / /_/ /_/ / /_/ / 
 /_____/_/|_/ .___/_/\____/_/\__/_____/_____/  
          /_/                                 


 
 Brought to you by Searchsploit - Find shellcodes and exploits

 """)
 search = raw_input(Fore.RED + "\n\nEnter search terms: ")
 os.system('./searchsploit ' + search)
 raw_input("\nPress enter to return to menu: ")
 return menu()




def cmsdet():
 os.system('clear')
 colreset()
 print(Fore.CYAN + """
   ________  ________ ____       __            __ 
  / ____/  |/  / ___// __ \___  / /____  _____/ /_
 / /   / /|_/ /\__ \/ / / / _ \/ __/ _ \/ ___/ __/
/ /___/ /  / /___/ / /_/ /  __/ /_/  __/ /__/ /_   
\____/_/  /_//____/_____/\___/\__/\___/\___/\__/  via Whatweb :P

 """)
 cmshost = raw_input(Fore.GREEN + "\nEnter Hostname: ") 
 colreset()
 os.system('whatweb -a 3 ' + cmshost)
 time.sleep(10)
 raw_input(Fore.MAGENTA + '\nPress enter to return to menu....')
 os.system('clear')
 return menu()
 
def dirbrute():
 os.system('clear')
 print(Fore.CYAN + """
   ___  _     _    
 |   \(_)_ _| |__ 
 | |) | | '_| '_ \
 |___/|_|_| |_.__/ - Brought to you by....... Fuck knows...
 """)                 
 dirhost = raw_input(Fore.GREEN + "\n\nEnter http:// or https:// domain: ")
 wordlist = raw_input("\nEnter Full Path of Wordlist: ")
 os.system('dirb ' + dirhost + ' ' + wordlist)
 raw_input(Fore.RED + "\n\nPress enter to return to the menu: ")
 return menu()
 
def hashgen():
 
 os.system('clear')
 print(Fore.CYAN + """
                                      
 _____         _   _____ _____ _____ 
|  |  |___ ___| |_|   __|   __|   | |
|     | .'|_ -|   |  |  |   __| | | |
|__|__|__,|___|_|_|_____|_____|_|___| import hashlib :P
                                     

  """)
 
 hashtype = raw_input(Fore.GREEN + "\n\nPlease choose hash type (MD5,SHA1,SHA256,SHA512): ")
 h = hashlib.new(hashtype)
 strhash = raw_input("\n\nEnter string to convert: ")
 h.update((strhash).encode('utf8'))
 print(h.hexdigest())
 
 raw_input(Fore.RED + "Press enter for menu")
 return menu()
 
def update():
 os.system('git pull')
 return menu()

def version():
 print("\nVersion 1.0\n")
 time.sleep(3)
 os.system('clear')
 return menu()
 
def quickmath():
 print("\n1+2 is 4, 4+2 is 7, quik maf")
 time.sleep(3)
 return menu()
def exit():
 print(Fore.RED + "\n\nExiting and Cleaning Up. Please Wait.....")
 time.sleep(5)
 print(Style.RESET_ALL)
 os.system('clear')
 sys.exit()

def main():
 user = "admin"
 password = "admin"
 answer1 = raw_input("Input Username: ")
 answer2 = raw_input("\nInput Password: ")

 if answer1==user and answer2==password:
  os.system('clear')
  print("""
  
 *        .              .   *
                .    ( Why the fuck we here )
    *     '       * ( Damn space weed )
                    ( Earth Beings abducted )
        * .    '     ( Anal probing was fun )
                     ( Bitch u a hobbit? )
    ' .                      /  .   *
               .-'~~~~'-.   /
    .      .-~ \__/  \__/`~-.         .
         .-~  (oo)(oo)       ~-.
        (_____/~~\/~~\______)
   _.-~`                         `~-._
  /O=O=O=O=O=O=O=O=O=O=O=O=O=O=O=O=O=O\     *
  \___________________________________/.
    JRO      \  x x x x x  /            `.
     .  *     \  x_x_x_x  /.    '  .     ___   .
               `.           `.         .'|  .
                 `.     .     `.       | \ / |
    ' .     *                          '.___.'
  """)
  print("\nWelcome back Shadow. \nLoading ShadowNet")
  time.sleep(3)
  return menu()
 else:
  print(Fore.RED + "\nWrong Creds, Fuck off skid")

 colreset()
 time.sleep(3)
 os.system('clear')
 menu()

main()



