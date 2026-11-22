#!/usr/bin/env bash
# Build and publish tr-proxy to Docker Hub by hand.
#
# Usage: scripts/publish.sh <version> [--no-latest] [--force] [--retag-latest-only] [--dry-run]
#
# Publishes from one git revision:
#   <IMAGE>:<version>
#   <IMAGE>:latest             (unless --no-latest)
#
# The order is "moving tag last": the versioned tag is built and pushed
# first, and :latest only moves once that has succeeded. Most users pull the
# moving tag, so it must never point at something half-shipped.
#
# If something fails partway:
#   - The tests or the build fail: the registry is unchanged; fix and re-run.
#   - Promoting :latest fails: :<version> exists, :latest is stale. Re-run
#     with --force --retag-latest-only to promote without rebuilding.
#
# Defaults can be overridden with environment variables:
#   IMAGE       Docker Hub image name      (default: timorinne/tr-proxy)
#   PLATFORMS   Buildx target platforms    (default: linux/amd64,linux/arm64)
#   BUILDER     Buildx builder name        (default: tr-proxy)
#   SKIP_TESTS  Set to 1 to skip the tests (not recommended)

set -euo pipefail

IMAGE_DEFAULT="timorinne/tr-proxy"
PLATFORMS_DEFAULT="linux/amd64,linux/arm64"
BUILDER_DEFAULT="tr-proxy"

usage() {
    cat >&2 <<EOF
Usage: $0 <version> [--no-latest] [--force] [--retag-latest-only] [--dry-run]

    <version>              Semver-style version without leading 'v' (e.g. 0.1.0).
    --no-latest            Do not move :latest (use for back-port releases).
    --force                Skip the clean-tree, main-branch, changelog and
                           upstream-tag-presence guards.
    --retag-latest-only    Skip the build; only re-promote :latest from the existing
                           :<version> tag. Useful when promotion failed but the
                           versioned build already shipped. Requires --force.
    --dry-run              Run the guards and the tests and build for all platforms,
                           but push nothing and create no git tag.

Environment overrides:
    IMAGE=$IMAGE_DEFAULT
    PLATFORMS=$PLATFORMS_DEFAULT
    BUILDER=$BUILDER_DEFAULT
    SKIP_TESTS=1
EOF
    exit 2
}

IMAGE="${IMAGE:-$IMAGE_DEFAULT}"
PLATFORMS="${PLATFORMS:-$PLATFORMS_DEFAULT}"
BUILDER="${BUILDER:-$BUILDER_DEFAULT}"

VERSION=""
TAG_LATEST=1
FORCE=0
RETAG_LATEST_ONLY=0
DRY_RUN=0

while (( $# > 0 )); do
    case "$1" in
        --no-latest)          TAG_LATEST=0 ;;
        --force)              FORCE=1 ;;
        --retag-latest-only)  RETAG_LATEST_ONLY=1 ;;
        --dry-run)            DRY_RUN=1 ;;
        -h|--help)            usage ;;
        -*)                   echo "unknown flag: $1" >&2; usage ;;
        *)
            if [[ -n "$VERSION" ]]; then
                echo "unexpected extra argument: $1" >&2
                usage
            fi
            VERSION="$1"
            ;;
    esac
    shift
done

[[ -n "$VERSION" ]] || usage

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]]; then
    echo "version must be semver like 1.2.3 or 1.2.3-rc1, got: $VERSION" >&2
    exit 1
fi

if [[ "$RETAG_LATEST_ONLY" -eq 1 && "$FORCE" -ne 1 ]]; then
    echo "--retag-latest-only requires --force (acknowledging that you know what you're doing)" >&2
    exit 1
fi
if [[ "$RETAG_LATEST_ONLY" -eq 1 && "$DRY_RUN" -eq 1 ]]; then
    echo "--retag-latest-only and --dry-run do not go together" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

GIT_TAG="v$VERSION"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found in PATH" >&2
    exit 1
fi
if ! docker buildx version >/dev/null 2>&1; then
    echo "docker buildx is required" >&2
    exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" && "$FORCE" -ne 1 ]]; then
    echo "refusing to publish from branch '$BRANCH'; pass --force to override" >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" && "$FORCE" -ne 1 ]]; then
    echo "refusing to publish from a dirty working tree; pass --force to override" >&2
    git status --short >&2
    exit 1
fi

if ! grep -q "^## \[$VERSION\]" CHANGELOG.md; then
    if [[ "$FORCE" -ne 1 ]]; then
        echo "CHANGELOG.md has no entry for $VERSION; add one, or pass --force" >&2
        exit 1
    fi
    echo "==> WARNING: CHANGELOG.md has no entry for $VERSION (continuing because --force)"
fi

REVISION="$(git rev-parse HEAD)"

# The release tag may be created beforehand, as long as it names the commit
# being released. A tag anywhere else means the version is taken.
if git rev-parse --verify --quiet "refs/tags/$GIT_TAG" >/dev/null; then
    TAGGED="$(git rev-parse "refs/tags/$GIT_TAG^{commit}")"
    if [[ "$TAGGED" == "$REVISION" ]]; then
        echo "==> git tag $GIT_TAG already names this commit; it will be pushed after the image"
    elif [[ "$FORCE" -ne 1 ]]; then
        echo "git tag $GIT_TAG already exists and names another commit (${TAGGED:0:7}, not ${REVISION:0:7}); delete it locally and remotely first, or pass --force" >&2
        exit 1
    else
        echo "==> WARNING: git tag $GIT_TAG names another commit (continuing because --force)"
    fi
fi

SOURCE_URL="$(git config --get remote.origin.url 2>/dev/null || true)"
if [[ "$SOURCE_URL" =~ ^git@([^:]+):(.+)\.git$ ]]; then
    SOURCE_URL="https://${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
elif [[ "$SOURCE_URL" =~ ^https?://.*\.git$ ]]; then
    SOURCE_URL="${SOURCE_URL%.git}"
fi

# Pre-flight: refuse to overwrite a versioned tag that is already on the
# registry. The moving tag is meant to move and is not checked.
if [[ "$RETAG_LATEST_ONLY" -ne 1 ]]; then
    if docker buildx imagetools inspect "${IMAGE}:${VERSION}" >/dev/null 2>&1; then
        if [[ "$FORCE" -ne 1 ]]; then
            echo "refusing to publish: ${IMAGE}:${VERSION} already exists on the registry. Pass --force to override." >&2
            exit 1
        fi
        echo "==> WARNING: ${IMAGE}:${VERSION} already exists upstream (continuing because --force)"
    fi
fi

if [[ "$RETAG_LATEST_ONLY" -ne 1 ]]; then
    if [[ "${SKIP_TESTS:-0}" != "1" ]]; then
        # Start from the registry's current base images, not cached copies
        # that may be months old; the buildx build below passes --pull for
        # the same reason.
        echo "==> pulling base images"
        docker pull golang:1.27-alpine
        docker pull gcr.io/distroless/static-debian12:nonroot
        echo "==> checking formatting and running the Go tests"
        make check
        make test
        echo "==> checking for known vulnerabilities"
        make vulncheck
        echo "==> running the smoke test"
        tests/smoke.sh
    else
        echo "==> SKIP_TESTS=1; not running the tests"
    fi

    if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
        echo "==> creating buildx builder '$BUILDER'"
        docker buildx create --name "$BUILDER" >/dev/null
    fi
    docker buildx inspect --bootstrap "$BUILDER" >/dev/null

    BUILD_ARGS=(
        --builder "$BUILDER"
        --pull
        --platform "$PLATFORMS"
        --build-arg "IMAGE_VERSION=${VERSION}"
        --build-arg "IMAGE_REVISION=${REVISION}"
        --build-arg "IMAGE_SOURCE=${SOURCE_URL}"
        --tag "${IMAGE}:${VERSION}"
    )
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "==> building ${IMAGE}:${VERSION} for $PLATFORMS (dry run: not pushing)"
        docker buildx build "${BUILD_ARGS[@]}" .
        echo "==> dry run done: built ${IMAGE}:${VERSION} from ${REVISION}; nothing pushed, no git tag"
        exit 0
    fi
    echo "==> building and pushing ${IMAGE}:${VERSION} for $PLATFORMS"
    docker buildx build "${BUILD_ARGS[@]}" --push .
fi

if [[ "$TAG_LATEST" -eq 1 ]]; then
    echo "==> promoting :latest -> ${IMAGE}:${VERSION}"
    docker buildx imagetools create --tag "${IMAGE}:latest" "${IMAGE}:${VERSION}"
fi

DIGEST="$(docker buildx imagetools inspect "${IMAGE}:${VERSION}" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
echo "==> pushed ${IMAGE}:${VERSION} ${DIGEST:-(digest lookup failed; image is published)}"

if [[ "$RETAG_LATEST_ONLY" -ne 1 ]]; then
    if git rev-parse --verify --quiet "refs/tags/$GIT_TAG" >/dev/null; then
        echo "==> git tag $GIT_TAG exists; pushing it"
    else
        echo "==> tagging and pushing git tag $GIT_TAG"
        git tag -a "$GIT_TAG" -m "Release $GIT_TAG"
    fi
    if git config --get remote.origin.url >/dev/null 2>&1; then
        git push origin "$GIT_TAG"
    else
        echo "    no 'origin' remote configured; git tag exists locally only" >&2
    fi
fi

echo "==> done: ${IMAGE}:${VERSION}$([[ $TAG_LATEST -eq 1 ]] && echo ' (latest moved)')"
