//! Shell tab-completion scripts (Batch-4): `phantom_vault completions <shell>`.
//!
//! Static subcommand/flag completion for PowerShell, Bash, and Nushell.
//! Deliberately NO live vault-title completion: titles are metadata, and
//! completing them would spray them into shell history files. Subcommands
//! and flags are public surface — safe to complete anywhere.

/// Subcommands mirrored from the CLI dispatch in `main.rs`. Single source of
/// truth for all three script generators below.
pub const COMMANDS: &[&str] = &[
    "run",
    "scan",
    "ssh-agent",
    "shred",
    "native-host",
    "completions",
];

/// `completions powershell` — native completer for phantom_vault (+ vault alias).
pub fn powershell_script() -> String {
    let cmds = COMMANDS
        .iter()
        .map(|c| format!("        '{c}'"))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        r#"# PhantomVault PowerShell completion — phantom_vault completions powershell > $PROFILE
Register-ArgumentCompleter -Native -CommandName phantom_vault, vault -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $words = $commandAst.ToString() -split '\s+'
    $cmds = @(
{cmds}
    )
    if ($words.Count -le 2) {{
        $cmds | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }}
    }} elseif ($words[1] -eq 'completions') {{
        @('powershell', 'bash', 'nushell') | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }}
    }}
}}
"#
    )
}

/// `completions bash` — `complete -F` function with per-subcommand flags.
pub fn bash_script() -> String {
    let cmds = COMMANDS.join(" ");
    format!(
        r#"# PhantomVault Bash completion — eval "$(phantom_vault completions bash)"
_phantom_vault() {{
    local cur prev cmds
    cmds="{cmds}"
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
        return 0
    fi
    case "${{COMP_WORDS[1]}}" in
        completions) COMPREPLY=( $(compgen -W "powershell bash nushell" -- "$cur") ) ;;
        native-host) COMPREPLY=( $(compgen -W "--print-manifest" -- "$cur") ) ;;
        run) COMPREPLY=( $(compgen -W "-e --" -- "$cur") ) ;;
        shred|scan) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    esac
    return 0
}}
complete -F _phantom_vault phantom_vault vault
"#
    )
}

/// `completions nushell` — `export extern` signatures.
pub fn nushell_script() -> String {
    r#"# PhantomVault Nushell completion — source via `use completions.nu`
export extern "phantom_vault" [
    ...args: string@"nu-complete phantom-vault-cmd"
]

def "nu-complete phantom-vault-cmd" [] {
    ["run", "scan", "ssh-agent", "shred", "native-host", "completions"]
}

export extern "phantom_vault completions" [
    shell?: string@"nu-complete phantom-vault-shell"
]

def "nu-complete phantom-vault-shell" [] {
    ["powershell", "bash", "nushell"]
}

export extern "phantom_vault native-host" [
    --print-manifest: string
]
"#
    .to_string()
}

/// Render for `powershell | bash | nushell` (case-insensitive, `ps`/`sh`/`nu` aliases).
pub fn render(shell: &str) -> Result<String, String> {
    match shell.trim().to_lowercase().as_str() {
        "powershell" | "ps" | "pwsh" => Ok(powershell_script()),
        "bash" | "sh" => Ok(bash_script()),
        "nushell" | "nu" | "nu-complete" => Ok(nushell_script()),
        other => Err(format!(
            "unknown shell '{other}' (powershell|bash|nushell)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_mirror_cli_dispatch() {
        // If main.rs gains a subcommand, add it here too (or this fails).
        for c in ["run", "scan", "ssh-agent", "shred", "native-host", "completions"] {
            assert!(COMMANDS.contains(&c), "missing {c}");
        }
    }

    #[test]
    fn powershell_registers_both_names() {
        let s = powershell_script();
        assert!(s.contains("Register-ArgumentCompleter"));
        assert!(s.contains("phantom_vault"));
        for c in COMMANDS {
            assert!(s.contains(c), "missing {c}");
        }
        assert!(s.contains("powershell") && s.contains("nushell"));
    }

    #[test]
    fn bash_completes_subcommands_and_flags() {
        let s = bash_script();
        assert!(s.contains("complete -F _phantom_vault phantom_vault"));
        for c in COMMANDS {
            assert!(s.contains(c), "missing {c}");
        }
        assert!(s.contains("--print-manifest"));
    }

    #[test]
    fn nushell_exports_externs() {
        let s = nushell_script();
        assert!(s.contains("export extern"));
        for c in COMMANDS {
            assert!(s.contains(c), "missing {c}");
        }
    }

    #[test]
    fn render_aliases_and_rejects() {
        assert!(render("ps").unwrap().contains("Register-ArgumentCompleter"));
        assert!(render("BASH").unwrap().contains("complete -F"));
        assert!(render("nu").unwrap().contains("export extern"));
        assert!(render("fish").is_err());
    }
}
