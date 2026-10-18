# Bash completion for LocalPIN; static public grammar only.
_localpin() {
    local cur prev command='' subcommand='' word skip_color=0 i
    local commands='menu setup status doctor enroll change disable migrate integration recover help completions'
    local options='--help -h --version -V --color --no-input'
    COMPREPLY=()
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}
    if [[ $cur == --color=* ]]; then
        mapfile -t COMPREPLY < <(compgen -W 'auto always never' -- "${cur#--color=}")
        for i in "${!COMPREPLY[@]}"; do COMPREPLY[i]="--color=${COMPREPLY[i]}"; done
        return
    fi
    if [[ $prev == --color ]]; then
        mapfile -t COMPREPLY < <(compgen -W 'auto always never' -- "$cur")
        return
    fi
    for ((i=1; i<COMP_CWORD; i++)); do
        word=${COMP_WORDS[i]}
        if ((skip_color)); then skip_color=0; continue; fi
        case $word in
            --color) skip_color=1; continue ;;
            --color=*|--no-input|--help|-h|--version|-V) continue ;;
        esac
        if [[ -z $command ]]; then command=$word
        elif [[ -z $subcommand ]]; then subcommand=$word
        fi
    done
    if [[ $command == help ]]; then
        command=$subcommand
        subcommand=''
    fi
    if [[ $prev == --backend ]]; then
        case $command in
            enroll) mapfile -t COMPREPLY < <(compgen -W 'auto tpm2-required software' -- "$cur") ;;
            migrate) mapfile -t COMPREPLY < <(compgen -W 'tpm2-required software' -- "$cur") ;;
        esac
        return
    fi
    # Never enumerate accounts for --user, files or secrets.
    [[ $prev == --user ]] && return
    case $command in
        '') options="$commands $options" ;;
        integration) [[ -z $subcommand ]] && options="status enable disable $options" ;;
        completions) [[ -z $subcommand ]] && options="bash zsh fish $options" ;;
        enroll|migrate) options="--backend $options" ;;
        status|doctor) options="--json $options" ;;
        recover) options="--user $options" ;;
    esac
    mapfile -t COMPREPLY < <(compgen -W "$options" -- "$cur")
}
complete -F _localpin localpin localpinctl
