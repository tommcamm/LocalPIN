#compdef localpin localpinctl
# Static public grammar only; never run LocalPIN or enumerate accounts.
_localpin() {
    local current=${words[CURRENT]} previous=${words[CURRENT-1]}
    local selected='' subcommand='' word skip_color=0 i
    local -a suggestions command_descriptions
    suggestions=(--help -h --version -V --color --no-input)
    command_descriptions=(
        'menu:Open the optional interactive menu'
        'setup:Set up or resume guided onboarding'
        'status:Show enrollment and activation'
        'doctor:Show readiness and next actions'
        'enroll:Create a credential with explicit protection'
        'change:Replace your credential'
        'disable:Disable your credential'
        'migrate:Replace protection and credential'
        'integration:Inspect integration or show administrator guidance'
        'recover:Recover one local account as administrator'
        'help:Show command help'
        'completions:Print static completion source'
    )
    if [[ $current == --color=* ]]; then
        compset -P '*='
        compadd auto always never
        return
    fi
    if [[ $previous == --color ]]; then compadd auto always never; return; fi
    for ((i=2; i<CURRENT; i++)); do
        word=${words[i]}
        if ((skip_color)); then skip_color=0; continue; fi
        case $word in
            --color) skip_color=1; continue ;;
            --color=*|--no-input|--help|-h|--version|-V) continue ;;
        esac
        if [[ -z $selected ]]; then selected=$word
        elif [[ -z $subcommand ]]; then subcommand=$word
        fi
    done
    if [[ $selected == help ]]; then selected=$subcommand; subcommand=''; fi
    if [[ $previous == --backend ]]; then
        case $selected in
            enroll) compadd auto tpm2-required software ;;
            migrate) compadd tpm2-required software ;;
        esac
        return
    fi
    [[ $previous == --user ]] && return
    case $selected in
        '') _describe 'command' command_descriptions; compadd -- $suggestions; return ;;
        integration) [[ -z $subcommand ]] && suggestions=(status enable disable $suggestions) ;;
        completions) [[ -z $subcommand ]] && suggestions=(bash zsh fish $suggestions) ;;
        enroll|migrate) suggestions=(--backend $suggestions) ;;
        status|doctor) suggestions=(--json $suggestions) ;;
        recover) suggestions=(--user $suggestions) ;;
    esac
    compadd -- $suggestions
}
_localpin "$@"
