# Source this file before P01 commands. No credentials are stored here.
_anynote_tools="${ANYNOTE_TOOLCHAINS:-/workspace/.toolchains}"
export CARGO_HOME="$_anynote_tools/cargo"
export RUSTUP_HOME="$_anynote_tools/rustup"
export PATH="$_anynote_tools/node-v24.21.0-linux-x64/bin:$CARGO_HOME/bin:$PATH"
unset _anynote_tools
