#!/bin/bash
#===============================================================================
# Color Definitions
# ANSI color codes for terminal output
#===============================================================================

# Check if terminal supports colors
if [[ -t 1 ]] && [[ "$(tput colors 2>/dev/null)" -ge 8 ]]; then
    # Basic colors
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[0;37m'
    
    # Bold colors
    BOLD_RED='\033[1;31m'
    BOLD_GREEN='\033[1;32m'
    BOLD_YELLOW='\033[1;33m'
    BOLD_BLUE='\033[1;34m'
    BOLD_MAGENTA='\033[1;35m'
    BOLD_CYAN='\033[1;36m'
    BOLD_WHITE='\033[1;37m'
    
    # Background colors
    BG_RED='\033[41m'
    BG_GREEN='\033[42m'
    BG_YELLOW='\033[43m'
    BG_BLUE='\033[44m'
    BG_MAGENTA='\033[45m'
    BG_CYAN='\033[46m'
    BG_WHITE='\033[47m'
    
    # Styles
    BOLD='\033[1m'
    DIM='\033[2m'
    UNDERLINE='\033[4m'
    BLINK='\033[5m'
    REVERSE='\033[7m'
    HIDDEN='\033[8m'
    
    # Reset
    NC='\033[0m'
    RESET='\033[0m'
else
    # No color support
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    MAGENTA=''
    CYAN=''
    WHITE=''
    BOLD_RED=''
    BOLD_GREEN=''
    BOLD_YELLOW=''
    BOLD_BLUE=''
    BOLD_MAGENTA=''
    BOLD_CYAN=''
    BOLD_WHITE=''
    BG_RED=''
    BG_GREEN=''
    BG_YELLOW=''
    BG_BLUE=''
    BG_MAGENTA=''
    BG_CYAN=''
    BG_WHITE=''
    BOLD=''
    DIM=''
    UNDERLINE=''
    BLINK=''
    REVERSE=''
    HIDDEN=''
    NC=''
    RESET=''
fi

# Export all color variables
export RED GREEN YELLOW BLUE MAGENTA CYAN WHITE
export BOLD_RED BOLD_GREEN BOLD_YELLOW BOLD_BLUE BOLD_MAGENTA BOLD_CYAN BOLD_WHITE
export BG_RED BG_GREEN BG_YELLOW BG_BLUE BG_MAGENTA BG_CYAN BG_WHITE
export BOLD DIM UNDERLINE BLINK REVERSE HIDDEN NC RESET
