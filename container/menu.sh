#!/bin/bash

G='\033[32m'
E='\033[0m'

ipaddr=$(ip --color=auto addr | grep global | grep -oP "(?<=inet )\d+\.\d+\.\d+\.\d+")

command=$1

if [[ "$#" -ne 1 ]]
then
    warning=$(echo -e "No command specified!")
fi

echo -e "${G}-------------------------------------${E}"
echo -e "${G}-----------${E} Select Option ${G}-----------${E}"
echo -e "${G}-------------------------------------${E}"
echo -e " ${G}+${E} IP:      $ipaddr"
echo -e " ${G}+${E} Command: ${1}${warning}"
echo -e "${G}-------------------------------------${E}"
echo -e " ${G}0.${E} Exit"
echo -e " ${G}1.${E} Shell"
echo -e " ${G}2.${E} Run once"
echo -e " ${G}3.${E} Run forever"
echo -e "${G}-------------------------------------${E}"

while true; do
    echo -ne "${G}[0/1/2/3]${E} "
    read -r selector
    case $selector in
        [0]* )
            exit;;
        [1]* )
            /bin/bash
            break;;
        [2]* )
            python /usr/local/bin/pwn-gdb $1
            break;;
        [3]* )
            while true; do
                python /usr/local/bin/pwn-gdb $1
            done
            break;;
        * )
            echo -ne "Answer not understood. ";;
    esac
done
