from ftplib import FTP

# FTP Credentials
FTP_HOST = "ftp.motorstateftp.com"
FTP_USER = "851409@motorstateftp.com"
FTP_PASS = ";~#K_#UB3I}C"

# Connect to FTP server
ftp = FTP(FTP_HOST)
ftp.login(FTP_USER, FTP_PASS)

# List possible directories
print("\n📂 Checking for Directories...\n")
possible_dirs = ["inventory", "data", "uploads", "files", "exports", "Motorstate"]

for directory in possible_dirs:
    try:
        ftp.cwd(directory)
        print(f"✅ Found Directory: {directory}")
        print("Contents:", ftp.nlst())  # List files inside
        break  # Stop once we find a valid directory
    except:
        print(f"❌ {directory} does not exist.")

# Close connection
ftp.quit()
print("\n✅ FTP Directory Check Complete.")
