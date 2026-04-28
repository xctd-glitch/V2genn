#!/bin/bash

find_project_local_recall_skills() {
    local workspace_root="$1"
    local skills_dir

    for skills_dir in \
        "$workspace_root/.claude/skills" \
        "$workspace_root/.codex/skills" \
        "$workspace_root/.gemini/skills"; do
        [ -d "$skills_dir" ] || continue
        find "$skills_dir" -maxdepth 1 -mindepth 1 -type d -name 'recall-*' 2>/dev/null | sort
    done
}

get_expected_recall_skill_name() {
    local workspace_root="$1"
    local config_path="$HOME/.termdock/memory/config.json"
    local workspace_root_real
    workspace_root_real="$(cd "$workspace_root" 2>/dev/null && pwd -P)"

    [ -f "$config_path" ] || return 1
    command -v jq >/dev/null 2>&1 || return 1

    local skill_name
    local configured_workspace
    local configured_workspace_real

    while IFS=$'\t' read -r skill_name configured_workspace; do
        [ -n "$skill_name" ] || continue
        [ -n "$configured_workspace" ] || continue

        configured_workspace_real="$(cd "$configured_workspace" 2>/dev/null && pwd -P)"

        if [ "$configured_workspace" = "$workspace_root" ] ||
           { [ -n "$workspace_root_real" ] && [ "$configured_workspace" = "$workspace_root_real" ]; } ||
           { [ -n "$configured_workspace_real" ] && [ "$configured_workspace_real" = "$workspace_root_real" ]; }; then
            printf '%s\n' "$skill_name"
            return 0
        fi
    done < <(
        jq -r '
            .skills
            | to_entries[]
            | .key as $name
            | (.value.workspaces // [])[ ]
            | [$name, .]
            | @tsv
        ' "$config_path" 2>/dev/null
    )

    return 1
}

ensure_not_stale_recall_skill() {
    local workspace_root="$1"
    local current_script_dir="$2"
    local local_skill_dirs=()
    local local_skill_dir
    local local_skill_names=()
    local local_skill_name
    local current_skill_name
    current_skill_name="$(basename "$current_script_dir")"
    local expected_skill_name
    expected_skill_name="$(get_expected_recall_skill_name "$workspace_root")"

    while IFS= read -r local_skill_dir; do
        [ -n "$local_skill_dir" ] || continue
        local_skill_dirs+=("$local_skill_dir")
        local_skill_name="$(basename "$local_skill_dir")"
        if [[ ! " ${local_skill_names[*]} " =~ " ${local_skill_name} " ]]; then
            local_skill_names+=("$local_skill_name")
        fi
    done < <(find_project_local_recall_skills "$workspace_root")

    if [ -n "$expected_skill_name" ]; then
        if [ "$current_skill_name" = "$expected_skill_name" ]; then
            return 0
        fi

        echo "Stale recall skill detected for workspace: $workspace_root" >&2
        echo "Current script: $current_script_dir" >&2
        echo "Expected project-local recall skill: $expected_skill_name" >&2
        if [ ${#local_skill_dirs[@]} -gt 0 ]; then
            echo "Project-local recall skill(s):" >&2
            for local_skill_dir in "${local_skill_dirs[@]}"; do
                echo "  - $local_skill_dir" >&2
            done
        fi
        echo "Use the expected project-local recall skill to avoid mixed memory paths." >&2
        return 1
    fi

    if [ ${#local_skill_names[@]} -gt 1 ]; then
        echo "Stale recall skill detected for workspace: $workspace_root" >&2
        echo "Current script: $current_script_dir" >&2
        echo "Multiple project-local recall skills found and the expected skill could not be resolved." >&2
        echo "Project-local recall skill(s):" >&2
        for local_skill_dir in "${local_skill_dirs[@]}"; do
            echo "  - $local_skill_dir" >&2
        done
        echo "Install jq or clean up stale local recall skills before retrying." >&2
        return 1
    fi

    [ ${#local_skill_dirs[@]} -eq 0 ] && return 0

    for local_skill_dir in "${local_skill_dirs[@]}"; do
        if [ "$local_skill_dir" = "$current_script_dir" ]; then
            return 0
        fi
    done

    echo "Stale recall skill detected for workspace: $workspace_root" >&2
    echo "Current script: $current_script_dir" >&2
    echo "Project-local recall skill(s):" >&2
    for local_skill_dir in "${local_skill_dirs[@]}"; do
        echo "  - $local_skill_dir" >&2
    done
    echo "Use the project-local recall skill to avoid mixed memory paths." >&2
    return 1
}
