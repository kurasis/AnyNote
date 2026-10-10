#!/usr/bin/env bash
# Linux cloud bootstrap. Install only pinned runtimes, outside the checkout.
set -euo pipefail

if [[ "$(uname -sm)" != 'Linux x86_64' ]]; then
  echo 'This cloud installer requires Linux x86_64; see P01 README for other hosts.' >&2
  exit 1
fi
for tool in curl sha256sum tar xz cc make pkg-config; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done

tools_root="${ANYNOTE_TOOLCHAINS:-/workspace/.toolchains}"
mkdir -p "$tools_root"
scratch_dir="$(mktemp -d /tmp/anynote-toolchains.XXXXXX)"
trap 'rm -rf "$scratch_dir"' EXIT

node_name=node-v24.21.0-linux-x64
node_archive="$node_name.tar.xz"
if [[ ! -x "$tools_root/$node_name/bin/node" ]]; then
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "https://nodejs.org/dist/v24.21.0/$node_archive" -o "$scratch_dir/$node_archive"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    https://nodejs.org/dist/v24.21.0/SHASUMS256.txt -o "$scratch_dir/SHASUMS256.txt"
  awk -v file="$node_archive" '$2 == file {print}' "$scratch_dir/SHASUMS256.txt" \
    > "$scratch_dir/node.sha256"
  [[ "$(wc -l < "$scratch_dir/node.sha256")" -eq 1 ]]
  (cd "$scratch_dir" && sha256sum --check node.sha256)
  tar -xJf "$scratch_dir/$node_archive" -C "$scratch_dir"
  [[ ! -e "$tools_root/$node_name" ]] || { echo 'Refusing to overwrite existing Node directory' >&2; exit 1; }
  mv "$scratch_dir/$node_name" "$tools_root/"
fi
[[ "$("$tools_root/$node_name/bin/node" --version)" == v24.21.0 ]]

export CARGO_HOME="$tools_root/cargo"
export RUSTUP_HOME="$tools_root/rustup"
if [[ ! -x "$CARGO_HOME/bin/rustup" ]]; then
  rustup_url=https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$rustup_url" -o "$scratch_dir/rustup-init"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$rustup_url.sha256" -o "$scratch_dir/rustup-init.sha256"
  (cd "$scratch_dir" && sha256sum --check rustup-init.sha256)
  chmod +x "$scratch_dir/rustup-init"
  "$scratch_dir/rustup-init" -y --no-modify-path --profile minimal --default-toolchain 1.99.0
fi
"$CARGO_HOME/bin/rustup" toolchain install 1.99.0 --profile minimal --component clippy,rustfmt
"$CARGO_HOME/bin/rustc" +1.99.0 --version
"$CARGO_HOME/bin/cargo" +1.99.0 --version
"$tools_root/$node_name/bin/node" --version
echo 'Pinned P01 toolchains installed; source scripts/runtime-env.sh before use.'
