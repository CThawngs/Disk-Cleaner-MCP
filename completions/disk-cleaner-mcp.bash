complete -F _disk_cleaner_mcp disk-cleaner-mcp
_disk_cleaner_mcp() { COMPREPLY=($(compgen -W "--http --help" "${COMP_WORDS[COMP_CWORD]}")); }
