#!/bin/bash 
# identify colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
#identify variables
domain=""
subfinder=/root/testing/subfinder.txt
sublist3r=/root/testing/sublist3r.txt
amass=/root/testing/amass.txt
combined=/root/testing/combined.txt
alive=/root/testing/alive.txt
final_extract=/root/testing/final.txt
subjack=/root/testing/subjack.txt 
# Process command-line options
while getopts ":d:" opt; do
  case $opt in
    d)
      domain="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Check if the domain is provided
if [ -z "$domain" ]; then
  echo "Error: Domain is required. Use -d option."
  exit 1
fi

# Your script logic here using the provided domain
echo -e " ${RED}***************************************************************************************************************************************"
echo "@@@@ @@@@ @                @@@@@  @@@@@ @@@@@ @@@@   @@      @  @@@@@"
echo " @          @ @          @@                @                      @                              @                    @          @  @    @  @"
echo " @@@@ @@@@@                 @@@@       @@@@@         @                    @          @   @   @  @@@@" 
echo " @               @           @@                @                                           @         @                    @          @     @ @ @ "
echo " @               @           @@@@@ @@@@@  @@@@@          @             @@@@  @       @@ @@@@@"      
echo -e "*****************************************************************************************************************************************${NC}"
echo -e "${GREEN}Domain Name: $domain${NC}"
host $domain > /root/testing/host.txt
file=/root/testing/host.txt
if [ -f $file ]; then 
	ipv4=$(cat $file | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
	ipv6=$(cat $file | grep -oE '\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b')
fi
# make subdomain enumration

echo -e "${BLUE}[INFO]${NC}Doing Subdomain Enumeration" 
# note that ----->> we using regax with Grep to just extract the only the subdomains 
# using sublist3r tool 
sublist3r -d $domain | grep '[\.]' | grep -v '[\-]' > $sublist3r
echo -e "${BLUE}[INFO]${NC}SubList3r DONE"

#using subfinder 

subfinder -d $domain 2>&1 |   grep -oE '[a-zA-Z0-9.-]+\.'"$domain"'$' > $subfinder
echo -e "${BLUE}[INFO]${NC}SubFinder DONE"

# using amass

#amass enum -d $domain | grep -oP '^[^\s]+' | grep -E -v '^[0-9]+$|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$|^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})+(/[0-9]+)?$|^[0-9a-fA-F:]+(/[0-9]+)?$' > $amass
#echo -e "${BLUE}[INFO]${NC} Amass DONE"

# combine all files and removing the duplicated
#if only the enumeration operation done successfuly
if [ $? -eq 0 ]; then 
	echo -e "${BLUE}[INFO]${NC}SubDomains Enum Done"
	cat $sublist3r $subfinder > $combined
	sort -u -o $combined $combined
else 
	exit 1
fi 
# check for alive domains 
echo -e "${BLUE}[INFO]${NC} Checking for alive subdomains"
massdns -r /usr/share/seclists/Miscellaneous/dns-resolvers.txt -t ANY -o S -w $alive $combined > /dev/null 2>&1

# sorting the all subdomains 

cat $alive  |  grep -P -o '(?<=\s|^)[^\s]+\.' | sed 's/\.$//' | grep -Ev '^[0-9]+(\.[0-9]+){0,3}(/\d{1,2})?$|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/\d{1,3}$' | sort -u > $final_extract

# checking for Subdomain TakeOver 
echo -e "${BLUE}[INFO]${NC} Checking For subdomain TakeOver"
subjack -c /usr/share/subjack/fingerprints.json -w $final_extract -ssl > $subjack
if grep -q '\[Vulnerable\]' $subjack; then 
	echo "${YELLOW}[Success]${NC} ************Subdomains Vulnerable to Subdomain TakeOver *************"
        awk '/\[Vulnerable\]/{print $NF}' $subjack 
else 
	echo -e "${RED}[Failure]${NC}********** Not Vulnerable for Subdomain TakeOver**************"
fi


# doing directory brure force to every domain we have in the final_exract 
# Specify the output CSV file
echo -e "${BLUE}[INFO]${NC}Doing directory Brute force it may take while please wait..."
# Specify the output CSV file
output_csv="/root/testing/ffuf_results.csv"
echo "Subdomain,Status,URL,Host" > "$output_csv"

# Loop through each subdomain in the file
while IFS= read -r subdomain; do
    # Run ffuf and save the output to a temporary file
    temp_output="$(mktemp)"

    if [[ "$subdomain" == *api* ]]; then
        echo "api domain"
        ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u "https://$subdomain/FUZZ" --proxy http://127.0.0.1:8080 -o "$temp_output" > /dev/null 2>&1
    else
        echo "normal domain"
        ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u "https://$subdomain/FUZZ" --proxy http://127.0.0.1:8080 -o "$temp_output" > /dev/null 2>&1
    fi

    # Extract information using jq and append to the CSV
    jq -r '.results[] | ["'"$subdomain"'", .status, .url, .host] | @csv' "$temp_output" >> "$output_csv"

    # Optional: Sleep to avoid rate limiting or to be kind to the server
    sleep 1

    # Remove the temporary ffuf output file
    rm "$temp_output"

done < "$final_extract"
echo "${YELLOW}[Success]${NC} Direcroty Brute Force Done ;)"
