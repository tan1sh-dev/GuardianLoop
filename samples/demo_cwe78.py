import os

def ping_host(hostname):
    # VULNERABLE: user input passed directly to os.system
    os.system("ping -c 1 " + hostname)

if __name__ == "__main__":
    host = input("Enter hostname: ")
    ping_host(host)