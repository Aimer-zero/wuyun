#!/usr/bin/env bash
set -euo pipefail

DEFAULT_REPO="Aimer-zero/wuyun"
DEFAULT_BRANCH="main"

REPO="${WUYUN_REPO:-$DEFAULT_REPO}"
BRANCH="${WUYUN_BRANCH:-$DEFAULT_BRANCH}"
VERSION="${WUYUN_VERSION:-}"
PACKAGE_VERSION=""
TARGET="${WUYUN_TARGET:-both}"
INSTALL_DIR="${WUYUN_INSTALL_DIR:-}"
ARCHIVE_URL="${WUYUN_ARCHIVE_URL:-}"
SOURCE_DIR="${WUYUN_SOURCE_DIR:-}"
DRY_RUN=0
KEEP_TEMP=0

SKILLS=(
  "wuyun"
  "wuyun-cloud-vuln"
  "wuyun-web-api-audit"
  "wuyun-exploit-assist"
  "wuyun-js-reverse"
  "wuyun-browser-runtime"
  "wuyun-js-deobfuscation"
  "wuyun-protocol-analysis"
  "wuyun-auth-audit"
  "wuyun-ai-audit"
  "wuyun-recon"
  "wuyun-evasion"
  "wuyun-redteam-ops"
  "wuyun-skill-security-audit"
  "wuyun-supply-chain-audit"
)

die() {
  printf 'wuyun install: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Wuyun online installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/Aimer-zero/wuyun/main/install.sh | bash -s -- --version v0.2.0

Options:
  --version <tag>       Install a fixed GitHub release/tag, for example v0.2.0.
  --branch <branch>     Install from a branch when --version is not set. Default: main.
  --repo <owner/repo>   GitHub repository to install from. Default: Aimer-zero/wuyun.
  --target <name>       codex, claude, both, or all. Default: both.
  --install-dir <dir>   Install into a custom skills directory instead of target defaults.
  --archive-url <url>   Download a custom tar.gz archive URL.
  --source-dir <dir>    Install from an already checked-out Wuyun repository.
  --dry-run             Print what would happen without writing skill directories.
  --keep-temp           Keep the download work directory for inspection.
  -h, --help            Show this help.

Environment equivalents:
  WUYUN_REPO, WUYUN_BRANCH, WUYUN_VERSION, WUYUN_TARGET, WUYUN_INSTALL_DIR,
  WUYUN_ARCHIVE_URL, WUYUN_SOURCE_DIR
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

expand_path() {
  case "$1" in
    "~") printf '%s\n' "$HOME" ;;
    "~/"*) printf '%s/%s\n' "$HOME" "${1#~/}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

safe_dir() {
  local dir="$1"
  [ -n "$dir" ] || die "empty install directory"
  [ "$dir" != "/" ] || die "refusing to install into /"
  [ "$dir" != "$HOME" ] || die "refusing to install directly into HOME"
}

archive_url() {
  if [ -n "$ARCHIVE_URL" ]; then
    printf '%s\n' "$ARCHIVE_URL"
  elif [ -n "$VERSION" ]; then
    printf 'https://github.com/%s/archive/refs/tags/%s.tar.gz\n' "$REPO" "$VERSION"
  else
    printf 'https://github.com/%s/archive/refs/heads/%s.tar.gz\n' "$REPO" "$BRANCH"
  fi
}

source_label() {
  if [ -n "$VERSION" ]; then
    printf 'tag %s\n' "$VERSION"
  elif [ -n "$ARCHIVE_URL" ]; then
    printf 'custom archive\n'
  else
    printf 'branch %s\n' "$BRANCH"
  fi
}

target_dirs() {
  if [ -n "$INSTALL_DIR" ]; then
    expand_path "$INSTALL_DIR"
    return
  fi

  case "$TARGET" in
    codex|openai)
      printf '%s\n' "$HOME/.codex/skills"
      ;;
    claude)
      printf '%s\n' "$HOME/.claude/skills"
      ;;
    both|all)
      printf '%s\n' "$HOME/.codex/skills"
      printf '%s\n' "$HOME/.claude/skills"
      ;;
    *)
      die "unknown --target: $TARGET"
      ;;
  esac
}

install_skill_dir() {
  local src_root="$1"
  local dest_root="$2"
  local skill tmp_dest

  safe_dir "$dest_root"
  mkdir -p "$dest_root"

  for skill in "${SKILLS[@]}"; do
    [ -d "$src_root/$skill" ] || die "archive is missing skill directory: $skill"
    tmp_dest="$dest_root/.${skill}.install.$$"
    rm -rf "$tmp_dest"
    cp -R "$src_root/$skill" "$tmp_dest"
    rm -rf "$dest_root/$skill"
    mv "$tmp_dest" "$dest_root/$skill"
    printf 'installed %s -> %s/%s\n' "$skill" "$dest_root" "$skill"
  done

  {
    printf '{\n'
    printf '  "repo": "%s",\n' "$REPO"
    printf '  "branch": "%s",\n' "$BRANCH"
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "package_version": "%s",\n' "$PACKAGE_VERSION"
    printf '  "source": "%s",\n' "$(source_label)"
    printf '  "installed_at": "%s",\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf '  "skills": [\n'
    for i in "${!SKILLS[@]}"; do
      skill="${SKILLS[$i]}"
      if [ "$i" -lt "$((${#SKILLS[@]} - 1))" ]; then
        printf '    "%s",\n' "$skill"
      else
        printf '    "%s"\n' "$skill"
      fi
    done
    printf '  ]\n'
    printf '}\n'
  } >"$dest_root/.wuyun-install.json"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift
      ;;
    --branch)
      [ "$#" -ge 2 ] || die "--branch requires a value"
      BRANCH="$2"
      shift 2
      ;;
    --branch=*)
      BRANCH="${1#*=}"
      shift
      ;;
    --repo)
      [ "$#" -ge 2 ] || die "--repo requires owner/repo"
      REPO="$2"
      shift 2
      ;;
    --repo=*)
      REPO="${1#*=}"
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires a value"
      TARGET="$2"
      shift 2
      ;;
    --target=*)
      TARGET="${1#*=}"
      shift
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || die "--install-dir requires a directory"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --install-dir=*)
      INSTALL_DIR="${1#*=}"
      shift
      ;;
    --archive-url)
      [ "$#" -ge 2 ] || die "--archive-url requires a URL"
      ARCHIVE_URL="$2"
      shift 2
      ;;
    --archive-url=*)
      ARCHIVE_URL="${1#*=}"
      shift
      ;;
    --source-dir)
      [ "$#" -ge 2 ] || die "--source-dir requires a directory"
      SOURCE_DIR="$2"
      shift 2
      ;;
    --source-dir=*)
      SOURCE_DIR="${1#*=}"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --keep-temp)
      KEEP_TEMP=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

need_cmd cp
need_cmd rm
need_cmd mv
need_cmd mkdir
need_cmd find
need_cmd head
need_cmd date

TMP_DIR=""
SRC_ROOT=""

cleanup() {
  if [ -n "$TMP_DIR" ] && [ "$KEEP_TEMP" -eq 0 ]; then
    rm -rf "$TMP_DIR"
  elif [ -n "$TMP_DIR" ]; then
    printf 'kept temp directory: %s\n' "$TMP_DIR"
  fi
}
trap cleanup EXIT

printf 'Wuyun installer\n'
printf '%s\n' "- repo: $REPO"
if [ -n "$SOURCE_DIR" ]; then
  printf '%s\n' "- source dir: $(expand_path "$SOURCE_DIR")"
else
  URL="$(archive_url)"
  printf '%s\n' "- source: $(source_label)"
  printf '%s\n' "- archive: $URL"
fi
printf '%s\n' "- target: $TARGET"
if [ -n "$INSTALL_DIR" ]; then
  printf '%s\n' "- custom install dir: $(expand_path "$INSTALL_DIR")"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '\nDry run only. Target directories:\n'
  while IFS= read -r dir; do
    printf '%s\n' "- $dir"
  done < <(target_dirs)
  exit 0
fi

if [ -n "$SOURCE_DIR" ]; then
  SRC_ROOT="$(expand_path "$SOURCE_DIR")"
  [ -d "$SRC_ROOT/wuyun" ] || die "--source-dir must point to a Wuyun repository root"
else
  need_cmd curl
  need_cmd tar
  need_cmd mktemp
  URL="$(archive_url)"
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wuyun-install.XXXXXX")"
  ARCHIVE="$TMP_DIR/wuyun.tar.gz"
  EXTRACT_DIR="$TMP_DIR/src"
  mkdir -p "$EXTRACT_DIR"
  curl -fsSL --retry 3 --connect-timeout 15 "$URL" -o "$ARCHIVE"
  tar -xzf "$ARCHIVE" -C "$EXTRACT_DIR"
  SRC_ROOT="$(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [ -n "$SRC_ROOT" ] || die "failed to locate extracted archive root"
fi

if [ -f "$SRC_ROOT/VERSION" ]; then
  PACKAGE_VERSION="$(head -n 1 "$SRC_ROOT/VERSION")"
fi

while IFS= read -r dir; do
  install_skill_dir "$SRC_ROOT" "$dir"
done < <(target_dirs)

printf '\nWuyun installed. Restart or reload your AI agent so it can rediscover the skills.\n'
