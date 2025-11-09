#!/bin/bash

# FORENSIC ENGINE LAUNCHER - Bash Edition
# Enhanced with better connectivity and error handling

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

# Check Python installation
check_python() {
    echo -e "${CYAN}Checking Python installation...${NC}"
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
        PYTHON_VERSION=$(python3 --version 2>&1)
        echo -e "${GREEN}✓ Python found: $PYTHON_VERSION${NC}"
        return 0
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
        PYTHON_VERSION=$(python --version 2>&1)
        echo -e "${GREEN}✓ Python found: $PYTHON_VERSION${NC}"
        return 0
    else
        echo -e "${RED}✗ Python not found in PATH${NC}"
        echo -e "${YELLOW}Please install Python from https://www.python.org/${NC}"
        return 1
    fi
}

# Check if pip is available
check_pip() {
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
        return 0
    elif command -v pip &> /dev/null; then
        PIP_CMD="pip"
        return 0
    else
        echo -e "${YELLOW}Warning: pip not found${NC}"
        return 1
    fi
}

# Display main menu
show_menu() {
    clear
    echo -e "${CYAN}=============================================================${NC}"
    echo -e "${CYAN}           FORENSIC ENGINE LAUNCHER v2.0${NC}"
    echo -e "${CYAN}=============================================================${NC}"
    echo ""
    echo -e "${YELLOW}  Available Tools:${NC}"
    echo -e "${YELLOW}  ---------------${NC}"
    echo -e "  ${BLUE}[1]${NC} ${CYAN}cracker.py${NC}        ${GRAY}- Hash Identifier & Cracker${NC}"
    echo -e "  ${BLUE}[2]${NC} ${CYAN}FileCarver.py${NC}     ${GRAY}- Quantum File Carver${NC}"
    echo -e "  ${BLUE}[3]${NC} ${CYAN}vmescapetester.py${NC} ${GRAY}- VM Escape Tester${NC}"
    echo -e "  ${BLUE}[4]${NC} ${CYAN}wipier.py${NC}         ${GRAY}- Log Tamperer/Sanitizer${NC}"
    echo ""
    echo -e "${YELLOW}  Actions:${NC}"
    echo -e "${YELLOW}  --------${NC}"
    echo -e "  ${BLUE}[5]${NC} ${MAGENTA}Show help for ALL tools${NC}"
    echo -e "  ${BLUE}[6]${NC} ${MAGENTA}Run tool with custom arguments${NC}"
    echo -e "  ${BLUE}[7]${NC} ${MAGENTA}Check Python environment${NC}"
    echo -e "  ${BLUE}[8]${NC} ${MAGENTA}Install requirements${NC}"
    echo -e "  ${BLUE}[9]${NC} ${MAGENTA}Open file location${NC}"
    echo -e "  ${BLUE}[0]${NC} ${RED}Exit${NC}"
    echo -e "${CYAN}=============================================================${NC}"
    echo ""
}

# Show help for a specific script
show_help() {
    local script_name=$1
    echo -e "${CYAN}=== $script_name Help ===${NC}"
    
    if [ -f "$script_name" ]; then
        $PYTHON_CMD "$script_name" --help
        if [ $? -ne 0 ]; then
            echo -e "${RED}Error displaying help for $script_name${NC}"
        fi
    else
        echo -e "${RED}Script not found: $script_name${NC}"
    fi
    
    echo ""
}

# Run script with custom arguments
run_script_with_args() {
    local script_name=$1
    
    if [ ! -f "$script_name" ]; then
        echo -e "${RED}Script not found: $script_name${NC}"
        return
    fi
    
    echo -e "${CYAN}Enter arguments for $script_name (or 'back' to return):${NC}"
    read -p "Arguments: " args
    
    if [ "$args" == "back" ] || [ -z "$args" ]; then
        return
    fi
    
    echo -e "${CYAN}Executing: $PYTHON_CMD $script_name $args${NC}"
    echo ""
    
    $PYTHON_CMD "$script_name" $args
}

# Check Python environment
show_python_environment() {
    clear
    echo -e "${CYAN}=== Python Environment Information ===${NC}"
    echo ""
    
    echo -e "${CYAN}Python Version:${NC}"
    $PYTHON_CMD --version
    
    echo ""
    echo -e "${CYAN}Python Executable Path:${NC}"
    which $PYTHON_CMD
    
    echo ""
    echo -e "${CYAN}Installed Packages (first 20):${NC}"
    if check_pip; then
        $PIP_CMD list | head -n 20
        echo ""
        echo -e "${YELLOW}Run '$PIP_CMD list' in terminal for full list.${NC}"
    else
        echo -e "${RED}pip not available${NC}"
    fi
    
    echo ""
}

# Install requirements
install_requirements() {
    clear
    echo -e "${CYAN}=== Installing Requirements ===${NC}"
    echo ""
    
    if [ -f "requirements.txt" ]; then
        echo -e "${CYAN}Found requirements.txt${NC}"
        read -p "Install packages from requirements.txt? (y/n): " confirm
        
        if [ "$confirm" == "y" ] || [ "$confirm" == "Y" ]; then
            if check_pip; then
                echo -e "${CYAN}Installing packages...${NC}"
                $PIP_CMD install -r requirements.txt
                
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✓ Installation complete!${NC}"
                else
                    echo -e "${RED}✗ Installation failed. Check error messages above.${NC}"
                fi
            else
                echo -e "${RED}pip not available. Cannot install packages.${NC}"
            fi
        fi
    else
        echo -e "${YELLOW}requirements.txt not found in current directory${NC}"
        echo -e "${CYAN}Creating basic requirements.txt...${NC}"
        
        cat > requirements.txt << EOF
# Basic requirements for forensic tools
numpy>=1.21.0
pandas>=1.3.0
psutil>=5.8.0
netifaces>=0.11.0
EOF
        
        echo -e "${GREEN}✓ Created requirements.txt with basic packages${NC}"
    fi
    
    echo ""
}

# Open file location
open_file_location() {
    current_path=$(pwd)
    echo -e "${CYAN}Opening: $current_path${NC}"
    
    if command -v xdg-open &> /dev/null; then
        xdg-open "$current_path"
    elif command -v open &> /dev/null; then
        open "$current_path"
    elif command -v nautilus &> /dev/null; then
        nautilus "$current_path" &
    else
        echo -e "${YELLOW}Cannot automatically open file manager${NC}"
        echo -e "${CYAN}Current directory: $current_path${NC}"
    fi
}

# Main script execution
main() {
    # Initial checks
    if ! check_python; then
        echo -e "${RED}Cannot continue without Python. Please install Python first.${NC}"
        read -p "Press Enter to exit..."
        exit 1
    fi
    
    check_pip
    
    # Main loop
    while true; do
        show_menu
        read -p "Select an option (0-9): " choice
        echo ""
        
        case $choice in
            1)
                show_help "cracker.py"
                read -p "Press Enter to continue..."
                ;;
            2)
                show_help "FileCarver.py"
                read -p "Press Enter to continue..."
                ;;
            3)
                show_help "vmescapetester.py"
                read -p "Press Enter to continue..."
                ;;
            4)
                show_help "wipier.py"
                read -p "Press Enter to continue..."
                ;;
            5)
                echo -e "${CYAN}=== Showing Help for ALL Tools ===${NC}"
                echo ""
                show_help "cracker.py"
                show_help "FileCarver.py"
                show_help "vmescapetester.py"
                show_help "wipier.py"
                read -p "Press Enter to continue..."
                ;;
            6)
                clear
                echo -e "${CYAN}=== Run Tool with Custom Arguments ===${NC}"
                echo ""
                echo "Available scripts:"
                echo "  [1] cracker.py"
                echo "  [2] FileCarver.py"
                echo "  [3] vmescapetester.py"
                echo "  [4] wipier.py"
                echo ""
                read -p "Select script (1-4): " script_choice
                
                case $script_choice in
                    1) run_script_with_args "cracker.py" ;;
                    2) run_script_with_args "FileCarver.py" ;;
                    3) run_script_with_args "vmescapetester.py" ;;
                    4) run_script_with_args "wipier.py" ;;
                    *)
                        echo -e "${RED}Invalid selection${NC}"
                        sleep 2
                        ;;
                esac
                read -p "Press Enter to continue..."
                ;;
            7)
                show_python_environment
                read -p "Press Enter to continue..."
                ;;
            8)
                install_requirements
                read -p "Press Enter to continue..."
                ;;
            9)
                open_file_location
                sleep 1
                ;;
            0)
                echo -e "${GREEN}Goodbye! Stay forensic!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option! Please select 0-9.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Welcome message
clear
echo ""
echo -e "${CYAN}=============================================================${NC}"
echo -e "${CYAN}  Welcome to Forensic Engine Launcher${NC}"
echo -e "${CYAN}=============================================================${NC}"
echo ""

# Start the application
main
