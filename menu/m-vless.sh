#!/bin/bash

clear
echo -e "========================================="
echo -e "            [ • Vless Menu • ]           "
echo -e "========================================="
echo -e ""
echo -e " [ 1 ] Create Account Vless "
echo -e " [ 2 ] Extending Account Vless "
echo -e " [ 3 ] Delete Account Vless "
echo -e " [ 0 ] Back To Menu"
echo -e ""
echo -e " Press X or [ Ctrl + C ] To Exit"
echo ""
echo -e "========================================="
echo -e ""
read -p " Select menu :  "  opt
echo -e ""
case $opt in
1) clear ; add-vless ;;
2) clear ; extend-vless ;;
3) clear ; del-vless ;;
0) clear ; menu ;;
x) exit ;;
*) echo "Anda salah input" ; sleep 0.5 ; m-vless ;;
esac
