# Fish completion for LocalPIN; static public grammar only.
# Built-in completion predicates inspect the command line, never LocalPIN state.
for localpin_command in localpin localpinctl
    complete -c $localpin_command -f
    complete -c $localpin_command -s h -l help -d 'Show help'
    complete -c $localpin_command -s V -l version -d 'Show version'
    complete -c $localpin_command -l color -r -a 'auto always never' -d 'Color policy'
    complete -c $localpin_command -l no-input -d 'Refuse interactive commands'
    set -l top 'not __fish_seen_subcommand_from menu setup status doctor enroll change disable migrate integration recover completions'
    complete -c $localpin_command -n $top -a menu -d 'Open the optional interactive menu'
    complete -c $localpin_command -n $top -a setup -d 'Set up or resume onboarding'
    complete -c $localpin_command -n $top -a status -d 'Show enrollment and activation'
    complete -c $localpin_command -n $top -a doctor -d 'Show readiness and next actions'
    complete -c $localpin_command -n $top -a enroll -d 'Create a credential'
    complete -c $localpin_command -n $top -a change -d 'Replace your credential'
    complete -c $localpin_command -n $top -a disable -d 'Disable your credential'
    complete -c $localpin_command -n $top -a migrate -d 'Replace protection and credential'
    complete -c $localpin_command -n $top -a integration -d 'Inspect integration or show administrator guidance'
    complete -c $localpin_command -n $top -a recover -d 'Recover an account as administrator'
    complete -c $localpin_command -n $top -a help -d 'Show command help'
    complete -c $localpin_command -n $top -a completions -d 'Print static completion source'
    complete -c $localpin_command -n '__fish_seen_subcommand_from status doctor' -l json -d 'Print nonsecret schema-2 JSON'
    complete -c $localpin_command -n '__fish_seen_subcommand_from enroll' -l backend -r -a 'auto tpm2-required software' -d 'Choose protection'
    complete -c $localpin_command -n '__fish_seen_subcommand_from migrate' -l backend -r -a 'tpm2-required software' -d 'Choose replacement protection'
    complete -c $localpin_command -n '__fish_seen_subcommand_from recover' -l user -r -d 'Existing local account name'
    complete -c $localpin_command -n '__fish_seen_subcommand_from integration; and not __fish_seen_subcommand_from status enable disable' -a 'status enable disable'
    complete -c $localpin_command -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish'
end
