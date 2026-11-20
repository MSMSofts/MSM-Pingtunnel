# AutoSSL 🔒✨

A simple and automatic script to obtain free SSL certificates from Let’s Encrypt using acme.sh on Linux servers without the need for a web server.

---

## Features 🚀

- Automatic installation and setup of acme.sh  
- Issue SSL certificates using standalone mode (no web server required)  
- Saves private key and certificate with `.pem` extension under `/root/cert/yourdomain/`  
- Colorful terminal messages for better user experience

---

## Requirements ⚙️

- Operating System: Ubuntu or other Linux distributions  
- Root access  
- Port 80 must be free and not used by any other service

---

# Manual installation
## How to Use 🛠️

2. Download the script directly:  
   ```
   curl -4 -O https://raw.githubusercontent.com/monhacer/AutoSSL/main/AutoSSL.sh
   ```
   or  
   ```
   wget -4 https://raw.githubusercontent.com/monhacer/AutoSSL/main/AutoSSL.sh
   ```

3. Make it executable:  
   ```
   chmod +x AutoSSL.sh
   ```

4. Run the script with root permissions:  
   ```
   sudo ./AutoSSL.sh
   ```

5. Enter your domain and email when prompted.

6. Your private key and certificate will be saved in `/root/cert/yourdomain/`.

---

## Auto Renewal 🔄

acme.sh automatically sets up a cron job for certificate renewal.  
To view cron jobs, run:  
`crontab -l`

---

# One-Command installer
   ```
   wget -4 https://raw.githubusercontent.com/monhacer/AutoSSL/main/AutoSSL.sh
   chmod +x AutoSSL.sh
   sudo ./AutoSSL.sh
   ```
---
## Important Notes ⚠️

- Make sure port 80 is open and not occupied by any other service.  
- This script only obtains and saves certificates; installing them on your services is your responsibility.

---

## License 📄

This project is licensed under the MIT License.

---

## Contact ✉️

For questions or suggestions, please visit my GitHub profile: [aioexp](https://github.com/monhacer)
