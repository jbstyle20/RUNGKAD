#!/bin/bash

clear
echo -e "========================================="
echo -e "            [ • Socks Menu • ]           "
echo -e "========================================="
echo -e ""
echo -e " [ 1 ] Create Account Socks "
echo -e " [ 2 ] Extending Account Socks "
echo -e " [ 3 ] Delete Account Socks "
echo -e " [ 0 ] Back To Menu"
echo -e ""
echo -e " Press X or [ Ctrl + C ] To Exit"
echo ""
echo -e "========================================="
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
1) clear ; add-socks ;;
2) clear ; extend-socks ;;
3) clear ; del-socks ;;
0) clear ; menu ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; m-socks ;;
esac
