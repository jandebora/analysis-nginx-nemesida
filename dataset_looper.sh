#!/bin/bash

# Script that loops into dataset location and launches and analyzes
# every .uri file contained in the folder
#
# usage: ./datase_looper dataset_name dataset_location
#
# required arguments:
# "dataset_name":         Name of dataset, valid values: "biblio" and "inves"
# "dataset_location":     Dataset location (Biblio.uri or INVES.uri folder)
#
# Author: Carlos Cagigao Bravo

# =====================================
# Constants
# =====================================
PARENT_LOCATION_OUTPUT="./data"
BIBLIO_OUTPUT_FOLDER="/Biblio"
BIBLIO_NO_SSL_FOLDER="/no-ssl/"
BIBLIO_SSL_FOLDER="/ssl/"
INVES_OUTPUT_FOLDER="/INVES"
INVES="inves"
BIBLIO="biblio"

# =====================================
# Arguments
# =====================================
DATASET="$1"
LOCATION="$2"

# =====================================
# Colours
# =====================================
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
grayColour="\e[0;37m\033[1m"

# =====================================
# Functions
# =====================================
menuSpawn(){
    printf "usage: ./dataset_looper dataset_name dataset_location\n"
    printf "\nScript that loops into dataset location and launches and analyzes\n"
    printf "every .uri file contained in the folder\n"
    printf "\nrequired arguments:\n"
    printf "\"dataset_name\":\t\tName of dataset, valid values: \"biblio\" and \"inves\"\n"
    printf "\"dataset_location\":\tDataset location (Biblio.uri or INVES.uri folder)\n"
}

checkArguments() {
    if [[ $EUID -ne 0 ]]; then
        printf "${yellowColour}This script must be run as root${endColour}\n"
        exit 1
    fi

    if [ "$#" -ne 2 ]; then
        menuSpawn
        exit 1
    fi

    printf "${greenColour}Checking arguments...${endColour}\n"
    if [ $DATASET != $BIBLIO ] && [ $DATASET != $INVES ]; then
        printf "${redColour}Invalid dataset name${endColour}\n"
        menuSpawn
        exit 1
    fi

    if [ ! -d $LOCATION ]; then
        printf "${redColour}Dataset location: $LOCATION does not exist${endColour}\n"
        menuSpawn
        exit 1
    fi
}

createFolders(){
    printf "${greenColour}Creating folders...${endColour}\n"
    if [ $1 = $BIBLIO ]; then
        dateListFolders="20170"
        for i in {1..7}; do
            mkdir -p $PARENT_LOCATION_OUTPUT$BIBLIO_OUTPUT_FOLDER$BIBLIO_SSL_FOLDER$dateListFolders$i
            mkdir -p $PARENT_LOCATION_OUTPUT$BIBLIO_OUTPUT_FOLDER$BIBLIO_NO_SSL_FOLDER$dateListFolders$i
        done
    fi

    if [ $1 = $INVES ]; then
        folder="/201805"
        mkdir -p $PARENT_LOCATION_OUTPUT$INVES_OUTPUT_FOLDER$folder
    fi
}

postStartScript() {
    printf "${yellowColour}Removing docker container...${endColour}\n"
    docker-compose down
    printf "${greenColour}Creating folder $1${endColour}\n"
    mkdir -p $1
    printf "${greenColour}Moving analysis files to $1${endColour}\n"
    mv analysis-$2.* $1
    printf "${greenColour}Moving log files to $1${endColour}\n"
    cp logs/* $1
    rm -rf logs
    printf "${greenColour}Starting docker...${endColour}\n"
    docker-compose up -d
    printf "${greenColour}Waiting for 10 seconds...${endColour}\n"
    sleep 10
}

getFileName() {
    file=$1
    fileName=$(basename -- "$file")
    fileName="${fileName%.*}"
}

getFileDate(){
    fileDate=$(echo $1 | sed -e s/[^0-9]//g)
}

launchBiblio() {
    biblioLocation="$LOCATION/*.uri"
    for file in $biblioLocation; do
        printf "\n${greenColour}Processing file $file...${endColour}\n"
        getFileName $file
        getFileDate $fileName
        fileNameSplitted=${fileName%%-*}
        python start.py -i $file -o "$fileNameSplitted-$fileDate.uri" -f "$fileNameSplitted-$fileDate.uri" -e "logs/error.log" -a "logs/access.log" -id "$fileDate"

        parentDateFolder="${fileDate:0:6}/"
        if [[ $fileName =~ ^'ssl' ]]; then
            outputLocation=$PARENT_LOCATION_OUTPUT$BIBLIO_OUTPUT_FOLDER$BIBLIO_SSL_FOLDER$parentDateFolder$fileDate
        else
            outputLocation=$PARENT_LOCATION_OUTPUT$BIBLIO_OUTPUT_FOLDER$BIBLIO_NO_SSL_FOLDER$parentDateFolder$fileDate
        fi
        postStartScript $outputLocation $fileDate

        mv $file $outputLocation
        rm *.uri
    done
}

launchInves() {
    invesLocation="$LOCATION/*.uri"
    for file in $invesLocation; do
        printf "\n${greenColour}Processing file $file...${endColour}\n"
        getFileName $file
        getFileDate $fileName
        fileNameSplitted=${fileName%%.*}
        python start.py -i $file -o "$fileNameSplitted-$fileDate.uri" -f "$fileNameSplitted-$fileDate.uri" -e "logs/error.log" -a "logs/access.log" -id "$fileDate"
        
        parentDateFolder="/${fileDate:0:6}/"
        outputLocation=$PARENT_LOCATION_OUTPUT$INVES_OUTPUT_FOLDER$parentDateFolder$fileDate
        postStartScript $outputLocation $fileDate
        mv $file $outputLocation
        rm *.uri
    done
}

# =====================================
# Main
# =====================================
checkArguments $@
createFolders $DATASET

if [ $DATASET = $BIBLIO ]; then
    launchBiblio
elif [ $DATASET = $INVES ]; then
    launchInves
else
    printf "${redColour}Invalid dataset provided${endColour}"
fi