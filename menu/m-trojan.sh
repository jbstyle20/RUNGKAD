#!/bin/bash

clear
echo -e "========================================="
echo -e "           [ • Trojan Menu • ]           "
echo -e "========================================="
echo -e ""
echo -e " [ 1 ] Create Account Trojan "
echo -e " [ 2 ] Extending Account Trojan "
echo -e " [ 3 ] Delete Account Trojan "
echo -e " [ 0 ] Back To Menu"
echo -e ""
echo -e " Press X or [ Ctrl + C ] To Exit"
echo ""
echo -e "========================================="
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
1) clear ; add-trojan ;;
2) clear ; extend-trojan ;;
3) clear ; del-trojan ;;
0) clear ; menu ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; m-trojan ;;
esac
