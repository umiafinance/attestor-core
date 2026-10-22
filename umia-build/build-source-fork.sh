#!/usr/bin/env bash
set -euo pipefail

# One ordered source path serves every historical layer and the final image.
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
layer=${1:?usage: build-source-fork.sh layer [--prepare-only [destination] | --test | image-tag]}
shift
manifest_file="$script_dir/source-fork-manifest.json"

manifest_rows=$(node - "$manifest_file" "$layer" <<'NODE'
const fs = require('node:fs')
const [file, layer] = process.argv.slice(2)
const manifest = JSON.parse(fs.readFileSync(file, 'utf8'))
const layers = ['epoch', 'auth', 'log', 'host', 'deps', 'consolidate', 'diagnostics', 'hardening', 'trust', 'final']
const files = ['claim-epoch.patch', 'auth-lifetime.patch', 'log-privacy.patch', 'host-policy.patch', 'dependency-remediation.patch', 'source-consolidation.patch', 'admission-diagnostics.patch', 'sec-hardening.patch', 'certificate-trust.patch', 'attestor-telemetry.patch']
const count = layers.indexOf(layer) + 1
const digest = /^[a-f0-9]{64}$/
if (!count || !/^[a-f0-9]{40}$/.test(manifest.upstreamCommit) || manifest.patches.length !== layers.length
    || !digest.test(manifest.packageSha256) || !digest.test(manifest.packageLockSha256)) throw Error('invalid source manifest')
console.log(`UPSTREAM\t${manifest.upstreamCommit}`)
for (const [index, patch] of manifest.patches.entries()) {
    if (patch.layer !== layers[index] || patch.file !== files[index] || !digest.test(patch.sha256)
        || !Array.isArray(patch.tests) || patch.tests.some(test => !/^[a-z0-9-]+\.test\.ts$/.test(test))) throw Error('invalid source patch entry')
    if (index >= count) continue
    console.log(`PATCH\t${patch.file}\t${patch.sha256}`)
    for (const test of patch.tests) console.log(`TEST\t${test}`)
}
if (count >= 5) {
    console.log(`PACKAGE\t${manifest.packageSha256}`)
    console.log(`LOCK\t${manifest.packageLockSha256}`)
}
NODE
)

patches=()
tests=()
package_sha=
lock_sha=
while IFS=$'\t' read -r kind value digest; do
    case "$kind" in
        UPSTREAM) upstream_sha=$value ;;
        PATCH) patches+=("$value:$digest") ;;
        TEST) tests+=("src/tests/$value") ;;
        PACKAGE) package_sha=$value ;;
        LOCK) lock_sha=$value ;;
    esac
done <<< "$manifest_rows"

# BSD sha256sum (macOS) lacks --check --status; hashing stdin works on both.
check_sha256() {
    local actual
    actual=$(sha256sum < "$2")
    if [[ "${actual%% *}" != "$1" ]]; then
        echo "sha256 mismatch: $2" >&2
        exit 1
    fi
}

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
for entry in "${patches[@]}"; do
    patch_file=${entry%%:*}
    patch_sha=${entry#*:}
    check_sha256 "$patch_sha" "$script_dir/$patch_file"
done

git clone --quiet --filter=blob:none --no-checkout https://github.com/reclaimprotocol/attestor-core.git "$build_dir/upstream"
git -C "$build_dir/upstream" checkout --quiet "$upstream_sha"
test "$(git -C "$build_dir/upstream" rev-parse HEAD)" = "$upstream_sha"
mkdir "$build_dir/context"
git -C "$build_dir/upstream" archive HEAD | tar -x -C "$build_dir/context"
for entry in "${patches[@]}"; do
    patch_file=${entry%%:*}
    (
        cd "$build_dir/context"
        git apply --check --whitespace=error "$script_dir/$patch_file"
        git apply --whitespace=error "$script_dir/$patch_file"
    )
done
cp "$script_dir/entrypoint.sh" "$build_dir/context/entrypoint.sh"
if [[ -n "$package_sha" ]]; then
    check_sha256 "$package_sha" "$build_dir/context/package.json"
    check_sha256 "$lock_sha" "$build_dir/context/package-lock.json"
fi
node - "$manifest_file" "$layer" > "$build_dir/context/umia-source-manifest.json" <<'NODE'
const fs = require('node:fs')
const [file, layer] = process.argv.slice(2)
const manifest = JSON.parse(fs.readFileSync(file, 'utf8'))
const count = manifest.patches.findIndex(patch => patch.layer === layer) + 1
const source = {
    upstreamCommit: manifest.upstreamCommit,
    patches: manifest.patches.slice(0, count).map(({ file, sha256 }) => ({ file, sha256 }))
}
if (count >= 5) {
    source.packageSha256 = manifest.packageSha256
    source.packageLockSha256 = manifest.packageLockSha256
}
console.log(JSON.stringify(source))
NODE
# The image runs as node, so nothing copied in may keep owner-only modes.
chmod -R u=rwX,go=rX "$build_dir/context"

case "${1:-}" in
    --prepare-only)
        if [[ -n "${2:-}" ]]; then
            test ! -e "$2"
            cp -a "$build_dir/context" "$2"
            echo "Prepared pinned $layer source in $2"
        else
            echo "Prepared pinned $layer source"
        fi
        ;;
    --test)
        (
            cd "$build_dir/context"
            if [[ -n "$lock_sha" ]]; then
                cp package-lock.json "$build_dir/reviewed-package-lock.json"
            fi
            # Match the image dependency stage before the upstream .npmrc is copied.
            rm .npmrc
            npm ci --ignore-scripts --no-audit --no-fund
            npm run build
            if [[ "$layer" != epoch && "$layer" != auth ]]; then
                npm run run:tsc -- src/scripts/build-browser.ts
                npm run run:tsc -- src/scripts/build-jsc.ts
            fi
            node --experimental-strip-types --experimental-test-module-mocks --test "${tests[@]}"
            if [[ -n "$lock_sha" ]]; then
                npm prune --omit=dev --ignore-scripts --no-audit --no-fund
                node "$script_dir/verify-production-audit.mjs" "$build_dir/context" "$build_dir/reviewed-package-lock.json" "$lock_sha"
            fi
        )
        ;;
    *)
        if [[ "$#" -gt 1 ]]; then
            echo 'expected one image tag' >&2
            exit 2
        fi
        case "$layer" in
            epoch) default_tag=umia-attestor:f6ff0e3-epoch ;;
            auth) default_tag=umia-attestor:f6ff0e3-epoch-auth ;;
            log) default_tag=umia-attestor:f6ff0e3-epoch-auth-log ;;
            host) default_tag=umia-attestor:f6ff0e3-epoch-auth-log-host ;;
            deps) default_tag=umia-attestor:f6ff0e3-epoch-auth-log-host-deps ;;
            consolidate) default_tag=umia-attestor:f6ff0e3-consolidate ;;
            diagnostics) default_tag=umia-attestor:f6ff0e3-diagnostics ;;
            hardening) default_tag=umia-attestor:f6ff0e3-hardening ;;
            trust) default_tag=umia-attestor:f6ff0e3-trust ;;
            final) default_tag=umia-attestor:f6ff0e3-final ;;
        esac
        image_tag=${1:-$default_tag}
        build_args=()
        if [[ -n "${ATTESTOR_DOCKER_BUILD_NETWORK:-}" ]]; then
            build_args+=(--network "$ATTESTOR_DOCKER_BUILD_NETWORK")
        fi
        docker build ${build_args[@]+"${build_args[@]}"} -f "$script_dir/Dockerfile" -t "$image_tag" "$build_dir/context"
        [[ "$(docker image inspect "$image_tag" --format '{{.Architecture}}')" == amd64 ]] ||
            { echo "$image_tag is not amd64; the ECS task is x86_64" >&2; exit 1; }
        docker run --rm --entrypoint sh "$image_tag" -c 'test -x /app/entrypoint.sh && test -r /app/package.json' ||
            { echo "$image_tag is not runnable by its node user" >&2; exit 1; }
        ;;
esac
