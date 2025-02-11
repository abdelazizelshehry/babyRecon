#!/bin/bash 
# identify colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
#identify variables
TODAY=$(date)
# Process command-line options
while getopts ":d:l:" opt; do
  case $opt in
    d)
      DOMAIN="$OPTARG"
      ;;
    l) 
      LIST="OPTARG"
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
if [ -z "$DOMAIN" ]; then
  echo "Error: Domain is required. Use -d option."
  exit 1
fi

# Your script logic here using the provided domain
DIR=${DOMAIN}_recon
DWORD=$(echo "${DOMAIN}" | grep -oP '^\w+(?=\.)')
echo -e "${YELLOW}[START]${NC}Creating new Directory For ${DOMAIN} at ${TODAY}"
mkdir -p ${DIR}
mkdir -p ${DIR}/host
host $DOMAIN > $DIR/host/IPsOFhost
file=$DIR/host/IPsOFhost
if [ -f $file ]; then 
	ipv4=$(cat $file | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' > ${DIR}/host/ipv4)
	ipv6=$(cat $file | grep -oE '\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b' > ${DIR}/host/ipv6)
	echo -e "${BLUE}[INFO]${NC}Doing NMAP for IPV4 found in IPsOFhost.txt in Host DIR it may take few time. Please Wait"
	#while read -r IP; do nmap -sV -Pn -sC -O -T2 "$IP" -oA "$IP_NMAPresults"; done < ${DIR}/host/ipv4
fi
# make subdomain enumration

echo -e "${BLUE}[INFO]${NC}Doing Subdomain Enumeration" 
# note that ----->> we using regax with Grep to just extract the only the subdomains 
# using sublist3r tool 
sublist3r -d $DOMAIN | grep '[\.]' | grep -v '[\-]' > ${DIR}/sublist3rDomains.txt
echo -e "${BLUE}[INFO]${NC}SubList3r DONE"

#using subfinder 

subfinder -d $DOMAIN 2>&1 | grep -oE '[a-zA-Z0-9.-]+\.'"${DOMAIN}"'$' > ${DIR}/subfinderDomains.txt
echo -e "${BLUE}[INFO]${NC}SubFinder DONE"

# using amass

timeout 1000s amass enum -passive -d $DOMAIN > ${DIR}/amassResults.txt
echo -e "${BLUE}[INFO]${NC} Amass DONE"
cat ${DIR}/amassResults.txt | grep -oP '^[^\s]+' | grep -E -v '^[0-9]+$|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$|^[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})+(/[0-9]+)?$|^[0-9a-fA-F:]+(/[0-9]+)?$' > ${DIR}/amassDomains.txt

# combine all files and removing the duplicated
#if only the enumeration operation done successfuly
if [ $? -eq 0 ]; then 
	echo -e "${BLUE}[INFO]${NC}SubDomains Enum Done You will find all subdomains in the file name called combined "
	cat ${DIR}/sublist3rDomains.txt ${DIR}/subfinderDomains.txt ${DIR}/amassDomains.txt | grep "${DWORD}" > ${DIR}/COMB.txt
	sort -u -o ${DIR}/COMB.txt ${DIR}/COMB.txt
else 
	echo "${RED}[ERROR]${NC}Error in Subdomain Enum Phase"
	exit 1
fi 
# permuate the subdomains 
#echo -e "${BLUE}[INFO]${NC} permuting subdomains by using ALTDNS tool"
#timeout 920s altdns -i ${DIR}/COMB.txt -o ${DIR}/OutputBeforeResolve -w /root/tools/altDNSword.txt -r -s ${DIR}/OutputAfterResolve
#cat ${DIR}/OutputAfterResolve | grep -Eo '^[^:]+' > ${DIR}/AltDnsAfterGrep
#if [$? -eq 0 ]; then 
#	cat ${DIR}/COMB.txt ${DIR}/AltDnsAfterGrep > ${DIR}/FINAL_COMB.txt 
#	echo -e "${BLUE}[INFO]${NC}AltDNS DONE successfully" 
#	sort -u -o ${DIR}/FINAL_COMB.txt ${DIR}/FINAL_COMB.txt 
#else 
#	echo "${RED}[ERROR]${NC}Error in AltDNS tool"
#	echo "stoping the Script........" 
#	exit 1
#fi 
# checking alive subdomains
echo -e "${BLUE}[INFO]${NC}Checking For Alive and non-alive subdomains with status Code with httpx tool" 
httpx -l ${DIR}/COMB.txt -sc -location -random-agent -rate-limit 20 -threads 5 -retries 3 2>/dev/null  > ${DIR}/httpxresults.txt
# sorting the subdomains based on the status code
echo -e "${BLUE}[INFO]${NC}HTTPX done"
endpoints() {
	# find all endpoints Using waybackurls and gau tools 
        while read -r DOMAINNAME; do echo "$DOMAINNAME" | waybackurls 2>/dev/null >> $1/${DOMAINNAME}; done < $2/domains.txt
        echo -e "${BLUE}[INFO]${NC} WayBackURLs DONE for $5 Status Code"
        while read -r DOMAINNAME; do echo "$DOMAINNAME" | gau 2>/dev/null >> $3/${DOMAINNAME}; done < $2/domains.txt
        echo -e "${BLUE}[INFO]${NC}Gau DONE for $5 Status Code"
	# Doing Paramspider to find parameters to FUZZ for all domains  specific to status code of it 
	while read -r DOMAINNAME; do paramspider -d "$DOMAINNAME" -s 2>/dev/null >> $4/${DOMAINNAME}; done < $2/domains.txt
	echo -e "${BLUE}[INFO]${NC}ParamSpider DONE for $5 status code"
}

# creating Fixed Function for viewing the File and remove the hidden character like colors form the htt>
echo -e "${BLUE}[INFO]${NC}Sorting and Creating DIRs for each status Code"
state_code() { 
    # Removing ANSI escape codes
    # Removing the hidden character of the file i mean the color's character of the httpx tool 
    sed_output=$(cat ${DIR}/httpxresults.txt | sed 's/\x1b\[[0-9;]*m//g')
    DIRSTATUSCODE=${DIR}/$1_URLS
    mkdir -p ${DIRSTATUSCODE}
    WAYBACK=${DIRSTATUSCODE}/waybackurlsResults
    mkdir -p ${WAYBACK}
    GAU=${DIRSTATUSCODE}/gauResults
    mkdir -p ${GAU}
    PARAMSPIDER=${DIRSTATUSCODE}/paramspiderresults
    mkdir -p ${PARAMSPIDER}
    # Perform the grep operation and check if it returns any results
    echo "$sed_output" | grep -E "\[$1\]" > ${DIRSTATUSCODE}/httpxURLS.txt
    if  [ $1 -eq 200 ]; then
        echo -e "${BLUE}[INFO]${NC}Starting Gau and waybackURLs tools for 200 statusCode"
        # find all the endpoints to specific URLs using wayback and gau
        cat ${DIRSTATUSCODE}/httpxURLS.txt | awk {'print $1'} > ${DIRSTATUSCODE}/URLs.txt
	sort -u -o ${DIRSTATUSCODE}/URLs.txt ${DIRSTATUSCODE}/URLs.txt
	cat ${DIRSTATUSCODE}/URLs.txt | sed 's|https\?://||' > ${DIRSTATUSCODE}/domains.txt
        endpoints ${WAYBACK} ${DIRSTATUSCODE} ${GAU} ${PARAMSPIDER} 200
    elif [ $1 -eq 301 ]; then 
        echo -e "${BLUE}[INFO]${NC} For 301 status Code"
        cat ${DIRSTATUSCODE}/httpxURLS.txt | awk {'print $3'} | sed 's/^\[//; s/\]$//' > ${DIRSTATUSCODE}/URLs.txt
	sort -u -o ${DIRSTATUSCODE}/URLs.txt ${DIRSTATUSCODE}/URLs.txt
	cat ${DIRSTATUSCODE}/URLs.txt | sed 's|https\?://||' > ${DIRSTATUSCODE}/domains.txt
        endpoints ${WAYBACK} ${DIRSTATUSCODE} ${GAU} ${PARAMSPIDER} 301
    elif [ $1 -eq 404 ]; then 
        echo -e "${BLUE}[INFO]${NC} For 404 status Code"
        cat ${DIRSTATUSCODE}/httpxURLS.txt | awk {'print $1'} > ${DIRSTATUSCODE}/URLs.txt
        sort -u -o  ${DIRSTATUSCODE}/URLs.txt ${DIRSTATUSCODE}/URLs.txt
	cat ${DIRSTATUSCODE}/URLs.txt | sed 's|https\?://||' > ${DIRSTATUSCODE}/domains.txt
	endpoints ${WAYBACK} ${DIRSTATUSCODE} ${GAU} ${PARAMSPIDER} 404
    elif [ $1 -eq 403 ]; then 
        echo  -e "${BLUE}[INFO]${NC} For 403 status code"
        cat ${DIRSTATUSCODE}/httpxURLS.txt | awk {'print $1'} > ${DIRSTATUSCODE}/URLs.txt 
        sort -u -o ${DIRSTATUSCODE}/URLs.txt  ${DIRSTATUSCODE}/URLs.txt
	cat ${DIRSTATUSCODE}/URLs.txt | sed 's|https\?://||' > ${DIRSTATUSCODE}/domains.txt
	endpoints ${WAYBACK} ${DIRSTATUSCODE} ${GAU} ${PARAMSPIDER} 403 
    fi 

}
if [ $? -eq 0 ]; then
        state_code 200 
        state_code 403
        state_code 301 
        state_code 404
        state_code 302
fi 

echo -e "${YELLOW}[INFO]${NC}RECON DONE WITH 0xbabyRecon ${TODAY}"
	#cat ${URLs_200} ${URLs_301} > ${DIR}/CoM_301_200
	#creating Directories for URLs based on the status code 
#	URLs_403=$(mkdir ${DIR}/403_URLs)
#	URLs_200=$(mkdir ${DIR}/200_URLs)
#	URLs_301=$(mkdir ${DIR}/301_URLs)
#	cat ${DIR}/httpxresults.txt | sed 's/\x1b\[[0-9;]*m//g' | grep -E '\[403\]' > ${URLs_403}/URLs.txt
#	cat ${DIR}/httpxresults.txt | sed 's/\x1b\[[0-9;]*m//g' | grep -E '\[302\]' | awk {'print $1'} > ${URLs_200}/URLs.txt
#	cat ${DIR}/httpxresults.txt | sed 's/\x1b\[[0-9;]*m//g' | grep -E '\[301\]' | awk {'print $3'} | sed 's/^\[//; s/\]$//' > ${URLs_301}/URLs.txt
#cat $alive  |  grep -P -o '(?<=\s|^)[^\s]+\.' | sed 's/\.$//' | grep -Ev '^[0-9]+(\.[0-9]+){0,3}(/\d{1,2})?$|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/\d{1,3}$' | sort -u > $final_extract

# checking for Subdomain TakeOver 
#echo -e "${BLUE}[INFO]${NC} Checking For subdomain TakeOver"
#subjack -c /usr/share/subjack/fingerprints.json -w $final_extract -ssl > $subjack
#if grep -q '\[Vulnerable\]' $subjack; then 
#	echo "${YELLOW}[Success]${NC} ************Subdomains Vulnerable to Subdomain TakeOver *************"
#        awk '/\[Vulnerable\]/{print $NF}' $subjack 
#else 
#	echo -e "${RED}[Failure]${NC}********** Not Vulnerable for Subdomain TakeOver**************"
#fi


# doing directory brure force to every domain we have in the final_exract 
# Specify the output CSV file
#echo -e "${BLUE}[INFO]${NC}Doing directory Brute force it may take while please wait..."
# Specify the output CSV file
#output_csv="/root/testing/ffuf_results.csv"
#echo "Subdomain,Status,URL,Host" > "$output_csv"

# Loop through each subdomain in the file
#while IFS= read -r subdomain; do
    # Run ffuf and save the output to a temporary file
#    temp_output="$(mktemp)"

#    if [[ "$subdomain" == *api* ]]; then
#        echo "api domain"
#        ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -u "https://$subdomain/FUZZ" --proxy http://127.0.0.1:8080 -o "$temp_output" > /dev/null 2>&1
#    else
#       echo "normal domain"
#        ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u "https://$subdomain/FUZZ" --proxy http://127.0.0.1:8080 -o "$temp_output" > /dev/null 2>&1
#    fi

    # Extract information using jq and append to the CSV
#    jq -r '.results[] | ["'"$subdomain"'", .status, .url, .host] | @csv' "$temp_output" >> "$output_csv"

    # Optional: Sleep to avoid rate limiting or to be kind to the server
#    sleep 1

    # Remove the temporary ffuf output file
#    rm "$temp_output"

#done < "$final_extract"
#echo "${YELLOW}[Success]${NC} Direcroty Brute Force Done ;)"
