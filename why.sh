#!/bin/bash

function show_menu {
    echo -e "\033[34mAvailable Python scripts:\033[0m"
    echo "1) cracker.py"
    echo "2) FileCarver.py"
    echo "3) vmescapetester.py"
    echo "4) wipier.py"
    echo "5) Show help for ALL scripts"
    echo "6) Exit"
}

function show_help {
    local script_name=$1
    echo -e "\033[32m=== $script_name help ===\033[0m"
    python3 "$script_name" --help
    echo
}

while true; do
    show_menu
    read -p "Select an option (1-6): " choice

    case $choice in
        1) show_help "cracker.py" ;;
        2) show_help "FileCarver.py" ;;
        3) show_help "vmescapetester.py" ;;
        4) show_help "wipier.py" ;;
        5)
            echo -e "\033[33m=== Showing help for ALL scripts ===\033[0m"
            show_help "cracker.py"
            show_help "FileCarver.py"
            show_help "vmescapetester.py"
            show_help "wipier.py"
            ;;
        6)
            echo -e "\033[32mGoodbye!\033[0m"
            exit 0
            ;;
        *) echo -e "\033[31mInvalid option! Please select 1-6.\033[0m" ;;
    esac
done
