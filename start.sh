#!/bin/bash

#Setting the parameters
URL="$1"
upload_server="$2"
remote_login="$3"

#Variable for the working directory as relevant
workdir="/opt/security/working"

#Checking that there are three paramters presented, and exiting if there aren't.
if [ "$#" -ne 3 ]; then
  echo "Error: Exactly three parameteres are needed."
  echo "Usage: $0 <URL> <Server> <User>"
  exit 1
fi

#Signal that the script is running
echo "Starting $(basename "$0")"

#Checking if the URL starts with https://
if [ "${URL:0:8}" == "https://" ]; then
  #Grabbing the IP after the first 8 characters
  IP_URL=${URL:8}
  
  #Using ping to check connectivity. 2 pings, waiting 2 seconds
  if ! ping -c 2 -W 2 $IP_URL > /dev/null; then
  
    #If it fails, it exits
    echo "Can't reach $URL"
    exit 1
  fi

#Else if the url starts with http, a warning message is printed and the scripts exits
elif [ "${URL:0:7}" == "http://" ]; then
  
  #Grabbing everything after the 7 first characters
  IP_URL=${URL:7}
  
  #Warning messages
  echo "Warning: URL connection is not using HTTPS://"
  echo "Provided URL needs to be HTTPS"
  
  #Exit can be commented out so the script runs without https
  #exit 1
  
else
  IP_URL=$URL
  
  #Warning messages
  echo "Warning: URL connection is not using HTTPS://"
  echo "Provided URL needs to be HTTPS"
  
  #Exit can be commented out so the script runs without Https
  exit 1
fi

#Checking with ping if there are a host, only 2 checks and waiting 2 seconds for each 
#if ! ping -c 2 -W 2 "${URL:8}" > /dev/null; then
#  echo "Can't reach $URL"
#  exit 1
#fi

#Check connectivity without HTTPS 
#if ! ping -c 2 -W 2 $URL > /dev/null; then
#  echo "Can't reach $URL"
#  exit 1
#fi



#Creating a script path for cron (It was problematic using ~/... Conflicting with what was the home dir and what cron regarded being home)
script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

#Setting up path for the tools (Validate being a copy of sha256sum and strcheck being a copy of grep)
validate="/opt/security/bin/validate" 
strcheck="/opt/security/bin/strcheck"

#Checking if the tools validate and strcheck exists
for file in "$validate" "$strcheck"; do
    if [ ! -f "$file" ]; then
        echo "$file does not exist" 
        exit 1
    fi
done


#Creating variables being date in a set format YYMMDD
DATE=$(date +"%Y%m%d")

#Setting hostname as the name of the machine
hostname=$(hostname)

#Creating a folder to put files into, easy to compress and remove after
archive_folder="$hostname-tth-$DATE"

#Timestamp variable according to error messages
timestamp=$(date +%Y%m%d-%H:%M)

#Files formatted according to said format
IoC_file="IOC-$DATE.ioc"
GPG_file="IOC-$DATE.gpg"

#variable for saving file locally if not able to connect to remote servers
localsave=0

#For resetting the filesystem on every exit, using the -f to not have errors if the files doesnt exist
cleanup() {
    rm -f $IoC_file
    rm -f $GPG_file
    
    #Using -rf to remove all files in folder
    rm -rf $workdir/$archive_folder

    #If the variable localsave is something else than 0, the tar file stays at the system.
    #This is so you can get access to a report even thought the remote server or problems with the ssh id file
    if [[ $localsave == 0 ]]; then 
        rm -f $tar_file
    fi
    rm -f $tar_file.sig
    rm -f $checksum_file
}
# Ensure the cleanup runs on script exit or error
trap cleanup EXIT

#Checking if the working folder is writable
if [ ! -d "$workdir" ]; then
        echo "$workdir does not exist" 
        exit 1
fi

if [ ! -w "$workdir" ]; then
    echo "The folder $workdir is not writeable"
    exit 1
fi

#Changing directory to working directory and creating a folder to include files in
cd "$workdir"
mkdir $archive_folder



#Checking if the first parameter had a dash at the end, removing it if there was 
if [ "${URL: -1}" == "/" ]; then
    URL="${URL:: -1}"
fi

#Function to download the relevant URLs
download(){
    #Taking the first variable to the function
    local url=$1
    
    #wget -q so there's no output 
    wget --no-check-certificate -q $url 
    
    #Error check, if the url file isn't found the program exits with the error message
    if [[ $? != 0 ]]; then
        echo "Failed-$hostname $timestamp: Couldn't find $url"
        exit 1
    fi
}

#Running the function for both files
download $URL/$IoC_file
download $URL/$GPG_file

#Verifying the GPG signature, surpressing output unless it's a failure.
gpgOUTPUT=$(gpg --verify "$GPG_file" "$IoC_file" 2>&1)

#If a success, prints validation message
if [ $? == 0 ]; then
    echo "GPG signature approved"

#If a failure, prints error message as wanted, as well as the output from gpg for debugging purposes.
else
    echo "Failed-$hostname $timestamp: GPG signature failed"
    echo "$gpgOUTPUT"
    exit 1
fi 

#Checking if the file date is correct 
#Checking the second line of the IOC file, being the date
FILE_CONTENT_DATE=$(awk 'NR==2' $IoC_file)

#If today's date is different then the content, then prints error message, and compares the dates and exits
if [[ "$DATE" != "$FILE_CONTENT_DATE" ]]; then
    echo "Failed-$hostname $timestamp:"
    printf "%-30s %s\n" "The file content date:" "$FILE_CONTENT_DATE "
    printf "%-30s %s\n" "Todays date is set as:" "$DATE"
    exit 1
fi

#Checking the hashes for the tools, takes two parameters. The tool, and the tool name it will search for
tool_validation() {
    local tool_name="$1"
    local search_word="$2"

    # Extract the expected hash for the tool from the IoC file. 
    local expected_hash=$(grep "^$search_word" "$IoC_file" | awk '{print $2}')
    
    # Generate the actual hash for the tool
    local actual_hash=$(sha256sum "$tool_name" | awk '{print $1}')
    
    # Compare the hashes and if they differ a comparison is printed and exiting program
    if [ "$expected_hash" != "$actual_hash" ]; then
        echo "Failed-$hostname $timestamp: "
        echo "Tool validation: $tool_name "
        echo "Expected:        $expected_hash" 
        echo "Hash found:      $actual_hash"
        exit 1
    fi
}

#Using the function for each of the tools 
tool_validation "$validate" "VALIDATE"
tool_validation "$strcheck" "STRCHECK" 




#Checking the hashes in the IOC files against the actual files
#Figured out a bit late that I propobly could use "find" here to make it more efficient, 
echo ""
echo "Checking IOC file hashes and strings..."
echo -e "\nChecks from the IOC file" > $archive_folder/IOC_check

#Reading one line at the time of the IoC file
while read -r line; do 
    
    #Setting filepath before IF statements since it regards both Strcheck and Validate
    filepath=$(echo "$line" | awk '{print $3}')

    #If the line starts with IOC, then do this...
    if [[ "$(echo "$line" | awk '{print $1}')" == "IOC" ]]; then
        
        #Creating variables from the IOC file
        
        hashsum=$(echo "$line" | awk '{print $2}')

        #Checking that the path is a directory, then running through the files in the directory
        if [ -d "$filepath" ]; then

            #Iterates through the files in the given filepath
            for file in "$filepath"/*; do

                #Checking if it's a file. Won't create hashes from other stuff then files
                if [ -f "$file" ]; then

                    #Create hash for the iterated file
                    file_hash=$($validate "$file" | cut -d ' ' -f 1)

                    #Checking the file against the hashsum
                    if [ "$hashsum" == "$file_hash" ]; then
                        echo "IOC $file_hash $file Hash match" >> $archive_folder/IOC_check
                        echo "IOC $hashsum $file"
                    fi
                fi
            done 

        #Checking if the given filepath is a file, and if so checking it against the hash     
        elif [ -f "$filepath" ]; then
            
            #Since filepath is a file, changing the variable to ahve similar code 
            file=$filepath

            #Create hash for the given file
            file_hash=$($validate "$file" | cut -d ' ' -f 1)

            #Checking the file against the hashsum
            if [ "$hashsum" == "$file_hash" ]; then
                echo "IOC $file_hash $file Hash match" >> $archive_folder/IOC_check
                echo "IOC $hashsum $file"
            fi
        fi
    
    #Check if the line of the IOC file starts with STR
    elif [[ "$(echo "$line" | awk '{print $1}')" == "STR" ]]; then       

        #Creating variable for the string and removing quotationmarks
        string=$(echo "$line" | awk '{print $2}' | sed -e 's/"//g')

        #Checking that the path is a directory
        if [ -d "$filepath" ]; then

            #Iterates through the files in the given filepath
            for file in "$filepath"/*; do

                #Checking if it's a file. Won't run through strings unless it's a file 
                if [ -f "$file" ]; then
                    
                    #Creating a variable to check for the string in the file
                    filestring=$($strcheck -F "$string" $file)

                    #If the variable has content, print relevant information to the report and stdout
                    if [ -n "$filestring" ]; then 
                        file_hash=$($validate "$file" | cut -d ' ' -f 1)
                        echo "IOC $file_hash $file String found: $string" >> $archive_folder/IOC_check
                        echo "IOC $file_hash $file"
                    fi
                fi
            done 
        
        #Checking if the given filepath is a file, and if so checking it against the hash     
        elif [ -f "$filepath" ]; then
            
            #Setting the variable to file so the code is similar if the path is dir or file
            file=$filepath
            
            #Creating a variable to check for the string in the file
            filestring=$($strcheck -F $string $file)

                    #If the variable has content, print relevant information to the report and stdout
                    if [ -n "$filestring" ]; then 
                        file_hash=$($validate "$file" | cut -d ' ' -f 1)
                        echo "IOC $file_hash $file String found: $string" >> $archive_folder/IOC_check
                        echo "IOC $file_hash $file"
                    fi
        fi
    fi
done<$IoC_file


#Create file for port information. Creating the file with a header
echo -e $"Ports open:" > $archive_folder/listeningports

#Listing listening ports with -l, -t and -u shows udp and tcp connections, while -n drops DNS resolution
if ! command -v netstat &> /dev/null; then
  echo -e "\nFailed-$hostname $timestamp: netstat is not installed on this system."
else
    netstat -lntu >> $archive_folder/listeningports
fi
#Create file for firewall information. Creating the file with a header
echo -e $"Firewall configuration:" > $archive_folder/firewall

#-L lists the rules and -n drops DNS resolution
iptables -L -n >> $archive_folder/firewall



#Validate packages in the folders

#Create file with header for the package checks
echo -e $"/sbin and /usr/sbin validation check:" > $archive_folder/binfailure

package_checks() {
    local path_to_files=$1        

    #For each file in the folder do
    for file in ${path_to_files}/*; do 

        #Check if there is a package name connected, and only picking the package name
        package=$(dpkg -S "$file" 2>/dev/null | cut -d ':' -f 1)

        #Only checking the package if the variable has content
        if [ -n "$package" ]; then

            #Debsum to check package, and only sending information if there is a miss-match
            debsums -s $package >> $archive_folder/binfailure
            printf "%-40s\r" "$file"
        fi
    done
}

#Checking if debsums is installed on the system
#If NOT installed, skipping the check and printing to stdout
if ! dpkg -l | grep -q debsums; then
    echo -e "\nFailed-$hostname $timestamp: debsums aren't installed on this system"
    echo -e "Skipping check of packages\n"
    echo "Did not run check due to debsums not being installed on the system" >> $archive_folder/binfailure

#If installed running the checks    
else
    echo -e "\nChecking packages in"
    #package_checks /usr/sbin
    #package_checks /sbin
    
    echo "" #Creating space to make it look better
fi

#Creating a file with a header 
echo -e "Checks for exectuable files in www/images/ or www/uploads/:" > "$archive_folder/executables"

#Function to check for executables in www/images and uploads
no_executables() {
    local path_to_dir=$1
    if [ -d $path_to_dir ]; then
    
        # Find all executable files in the directory and subdirectories
        find "$path_to_dir" -type f -executable | while read -r file; do

            #For each file found, prints it to the report, stdout and changes permission
            echo "$file shouldn't be executable. This is now changed" >> "$archive_folder/executables"
            chmod -x "$file" # Remove execute permission
            echo "$file shouldn't be executable. This is now changed"
        done
    else
        echo -e "\n Failed-$hostname $timestamp: Check for executables \n $path_to_dir does not exist\n"
    fi
}

#Running the function for relevant directories
no_executables /var/www/images/
no_executables /var/www/uploads/



#Looking for files created within the last 48 hours
#Date -d parses the string 48 hours ago and +%s to only get seconds
threshold=$(date -d "48 hours ago" +%s)

echo -e "SUID and GUID:" > $archive_folder/SUID_SGID_check

if [ -d /var/www ]; then
    # Find all files in the directory and reading it line by line with while
    find "/var/www" -type f | while read -r file; do

        # Get the birth time in seconds with -c %W
        birth_time=$(stat -c %W "$file")

        # Compare the birth time with the threshold
        if [[ "$birth_time" -gt "$threshold" ]]; then
            echo "File created in the last 48 hours: $file"
        fi
    done


    # Find files with SUID bit set in /var/www
    suid_files=$(find /var/www/ -type f -perm /4000 2>/dev/null)

    # If SUID files are found, append the information to SUID_SGID_check
    if [[ -n "$suid_files" ]]; then
        echo "User ID (4) | $suid_files" >> $archive_folder/SUID_SGID_check
    fi

    # Find files with SGID bit set in /var/www
    sgid_files=$(find /var/www/ -type f -perm /2000 2>/dev/null)

    # If SGID files are found, append the information to SUID_SGID_check
    if [[ -n "$sgid_files" ]]; then
        echo "Group ID (2) | $sgid_files" >> $archive_folder/SUID_SGID_check
    fi
else
    echo -e "Failed-$hostname $timestamp: /var/www doesn't exist\nCan't check for SUID & SGID\n"
fi
report_file=$archive_folder/iocreport.txt

#Creating IOC-report, with space under the header
echo "REPORT $DATE" > $report_file


add_to_report() {
  local file_path="$1"
  
  # Check if file only has a header (If something is found, it is appended to the file, else there's only a header)
  if [ "$(wc -l < "$file_path")" == 1 ]; then
    echo "Nothing to report/found" >> "$file_path"
  fi

   # Append file content to report 
  cat "$file_path" >> "$report_file"

  #Add an empty line to create some space between headings in the report
  echo "" >> "$report_file"
}

add_to_report $archive_folder/IOC_check
add_to_report $archive_folder/listeningports
add_to_report $archive_folder/firewall
add_to_report $archive_folder/binfailure
add_to_report $archive_folder/SUID_SGID_check
add_to_report $archive_folder/executables


tar_file=$archive_folder.tar.gz

#Removing if there are an earlier under the same name 
rm -f $tar_file

#Creating tar file
tar -czf "$tar_file" "$archive_folder"

#Had some local problems with creating checksum file, so had to change file privliges. 
#Setting checksum file variable
checksum_file=checksum.sha256

#Create checksum file
touch $checksum_file

#Change privilges so it can be edited
chmod 666 $checksum_file

#With these privliges, a checksum file could be created
sha256sum $tar_file > $checksum_file

#Change file privileges back
chmod 644 $checksum_file

#Setting keyid variable for gpg key, as requested
keyid="tht2024@tht.noroff.no"

# Check if the GPG key is available
if gpg --list-secret-keys "$keyid" >/dev/null 2>&1; then
    # If the key exists, create the signature file
    gpg -b --local-user "$keyid" "$tar_file"
else
    # If the key is not found, output an error message
    echo -e "Failed-$hostname $timestamp GPG key with ID '$keyid' not found. \nAborting signature creation." 
fi

#New variables needed for the remote directory to upload into
year=$(date +%Y)
month=$(date +%m)

#Setting the path where the files will be uploaded to
remote_path="~/submission/$hostname/$year/$month"


#Set variable as where the ssh information is set to be 
identity_file="/opt/security/${remote_login}.id"


#Grabbing only the IP so a ping check can check connectivity
if [ "${upload_server:0:8}" == "https://" ]; then
  #Grabbing everything after 8 characters
  IP_upload=${upload_server:8}

elif [ "${upload_server:0:7}" == "http://" ]; then
  #Grabbing everything after 7 characters
  IP_upload=${upload_server:7}
  echo "Warning: Upload server connection is not using HTTPS://"
else

  IP_upload=$upload_server
  echo "Warning: Upload server connection is not using HTTPS://"
  
fi

#Check if the upload address can be pinged
if ! ping -c 2 -W 2 $IP_upload > /dev/null; then
    
    #If not working, display error message to stdout
    echo "Failed-$hostname $timestamp Can't connect to $upload_server."
    echo "Tar file won't be uploaded to $upload_server"
    
    #Ask the user if they want to save the tar file locally
    read -p "Do you want to save to file locally? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        
        #Change variable so the tar file won't be deleted by the trap exit
        localsave=1
        echo "File saved as $workdir/$tar_file"
    fi
    
#Check if the ssh id file is present
elif [[ ! -f "$identity_file" ]]; then
    
    #If not working, display error message to stdout
    echo "Failed-$hostname $timestamp $identity_file does not exist"
    echo "Tar file won't be uploaded to $upload_server"
    
    #Ask the user if they want to save a new file locally
    read -p "Do you want to save to file locally?? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        
        #Change variable so the tar file won't be deleted by the trap exit
        localsave=1
        echo "File saved as $workdir/$tar_file"
    fi
else
    #Using rsync to transfer the relevant files, using -i to use the identity file instaed of password
    rsync -e "ssh -i $identity_file" "$tar_file" "$checksum_file" "${tar_file}.sig" "$remote_login@$IP_upload:$remote_path" 2>/dev/null
    #SSH to check the files, -q for silent and -i for the identity file. Other output is redirected
    
    #-i uses the identity file, bash -s functions here to lessen the output in stdout. It starts a shell, so we don't print MOTD
    ssh -i "$identity_file" -q "$remote_login@$IP_upload" bash -s 2>/dev/null << EOF 
        #Navigate to the directory where files are stored, if that doesn't work. Exit the ssh
            cd $remote_path || { echo -e "\nFailed-$hostname $timestamp:"; echo "Could not find directory $remote_path"; echo "File did not upload"; exit; }

            # Verify the GPG signature of the tar file
            if gpg --verify "${tar_file}.sig" "$tar_file" > /dev/null 2>&1; then
                echo -e "\nGPG Signature verified for $tar_file on $upload_server"
            else
                echo -e "\nFailed-$hostname $timestamp: GPG Signature verification failed on $upload_server while checking $tar_file"
            fi

            # Verify the SHA256 checksum
            if sha256sum -c "$checksum_file" > /dev/null 2>&1; then
                echo "Hash verified for $tar_file on $upload_server"
            else
                echo "Failed-$hostname $timestamp: SHA256 \nChecksum verification failed on $upload_server while checking $tar_files"
            fi

EOF
fi


#Configure the script to run at 2 AM via cron if not already set up
cron_job="0 2 * * * $script_path $1 $2 $3"

# Check if the cron job is already present
existing_cron=$(crontab -l | grep -F "$cron_job" 2>/dev/null)


if [ -z "$existing_cron" ]; then
  # Add the cron job if it's not present
  (crontab -l; echo "$cron_job") | crontab -
  echo -e "\nCron job added to run daily at 2 AM"

fi
echo ""

file_size=$(du -m $tar_file | cut -f1)
echo "Filename: $tar_file File size: $file_size MB"
echo "TTH IoC Check $hostname $timestamp OK"



