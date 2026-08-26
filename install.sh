#!/usr/bin/env bash

# Install the reverse-engineering skill for Claude Code, OpenCode, and other agents.
# Usage: ./install.sh [--copy]
# Default: create symlinks. Pass --copy to copy files instead.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_NAME="reverse-engineering"
SKILL_SOURCE="${REPO_ROOT}/skills/${SKILL_NAME}"

USE_COPY=false
if [[ "${1:-}" == "--copy" ]]; then
    USE_COPY=true
fi

if [[ ! -d "${SKILL_SOURCE}" ]]; then
    echo "Error: skill source directory not found at ${SKILL_SOURCE}"
    exit 1
fi

install_skill() {
    local target_dir="$1"
    local target_path="${target_dir}/${SKILL_NAME}"

    mkdir -p "${target_dir}"

    if [[ -e "${target_path}" ]] || [[ -L "${target_path}" ]]; then
        read -rp "${target_path} already exists. Replace? [y/N] " answer
        case "${answer}" in
            [yY]*) ;;
            *)
                echo "Skipping ${target_dir}"
                return
                ;;
        esac
        rm -rf "${target_path}"
    fi

    if [[ "${USE_COPY}" == true ]]; then
        cp -R "${SKILL_SOURCE}" "${target_path}"
        echo "Copied skill to ${target_path}"
    else
        ln -s "${SKILL_SOURCE}" "${target_path}"
        echo "Linked skill to ${target_path}"
    fi
}

echo "Installing ${SKILL_NAME} skill..."
echo "Source: ${SKILL_SOURCE}"
echo "Mode: $([[ ${USE_COPY} == true ]] && echo copy || echo symlink)"
echo ""

install_skill "${HOME}/.claude/skills"
install_skill "${HOME}/.config/opencode/skills"
install_skill "${HOME}/.agents/skills"

echo ""
echo "Installation complete."
echo "Restart Claude Code / OpenCode / your agent for the skill to load."
