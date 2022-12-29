#!/bin/bash

clear
echo -e "========================================="
echo -e "            [ • Vmess Menu • ]           "
echo -e "========================================="
echo -e ""
echo -e " [ 1 ] Create Account Vmess "
echo -e " [ 2 ] Extending Account Vmess "
echo -e " [ 3 ] Delete Account Vmess "
echo -e " [ 0 ] Back To Menu"
echo -e ""
echo -e " Press X or [ Ctrl + C ] To Exit"
echo ""
echo -e "========================================="
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
1) clear ; add-vmess ;;
2) clear ; extend-vmess ;;
3) clear ; del-vmess ;;
0) clear ; menu ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; m-vmess ;;
esac
