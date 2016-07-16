#!/bin/bash 

# User should pass PMR number to the script
PMR=$1

# If PMR number is not passed at the command line, prompt for a PMR number
if [ -z "$PMR" ]; then
printf "Please enter a PMR number to lookup: \t"
read PMR
fi

# Check the length and append ,000 if no country is entered
len=$(expr length $PMR)
if [ $len -eq 9 ]; then
country=",000"
newNum=$PMR$country
PMR=$newNum
fi


#chromium-browser https://ecurep.mainz.de.ibm.com/aex/toPMR.jsp?PMRString=$PMR 2>/dev/null & 
PMRURL=$(echo "$PMR" | sed "s/,/\%2C/g")
#echo $PMRURL
####firefox https://ecurep.mainz.de.ibm.com/aex/toPMR.jsp?PMRString=$PMR 2>/dev/null & 
#https://ecurep.mainz.de.ibm.com/ae5/#id=74941%2C057%2C649# pmrdir.sh must be in PATH, if not provide full PATH to file
firefox https://ecurep.mainz.de.ibm.com/ae5/#id=$PMRURL
pmrdir.sh $PMR
exit 0
