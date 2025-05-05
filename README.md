First run:
-	To run the script it needs to be executable, and can be ran with ./tth-xxxx.sh
-	To run it the first time, it needs to be ran as sudo, it will then configure cron to run it at 2 AM every day. 
-	First time connecting with ssh you need to input Yes to establish connection

Tool requirements
-	The system needs debsums to be able to check the packages. 
o	The script will run without it, and skip the check. 
o	Debsums can be downloaded with sudo apt-get install debsums 
-	The system needs netstat for checking what ports it’s listening on. 
o	This check will be skipped if netstat isn’t on the system. 
o	Netstat can be downloaded with sudo apt install net-tools

Configuring Crontab to send mail
-	The cronjob that is set to run at 2 AM. This can be changed running the command “sudo crontab -e “ or changing it in the script. 
-	For crontab to send it as an email you have to have configured the machine to be able to send mail. 
-	The test environment the script was created in used ssmtp, with gmail. It was configured according to Tutorial 5, Task 5 Email with SSMTP. 
-	When mail is configured on the machine, use the command “sudo crontab -e” and add the line “MAILTO=yourmail@example.com”. 
-	Remember to check junkmail if mail doesn’t show up in your inbox.

Disclaimer:
1.	Script wasn’t configured with a HTTPS environment. It will check for https in the provided URL, and not connect unless it starts with HTTPS. If the script doesn’t find anything due to HTTPS, you can comment out “exit 1” on line 42 or 50, and run the URL as http://ip_address or without http:// at all. 
 

2.	The upload server needs the folder already made for it to be uploaded. If the folder ~/submission/hostname/year/month doesn’t exist, the script will not upload anything. This way the iocreport and relevant files will be lost. 
