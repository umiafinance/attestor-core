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
const digest = /^[a-f0-9]{64}$/
const name = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
if (!/^[a-f0-9]{40}$/.test(manifest.upstreamCommit) || !Array.isArray(manifest.patches)
    || !manifest.patches.length) throw Error('invalid source manifest')
const layers = new Set()
const files = new Set()
for (const patch of manifest.patches) {
    if (!patch || typeof patch.layer !== 'string' || !name.test(patch.layer) || !/^[a-z0-9-]+\.patch$/.test(patch.file)
        || layers.has(patch.layer) || files.has(patch.file) || !digest.test(patch.sha256)
        || !Array.isArray(patch.tests) || patch.tests.some(test => !/^[a-z0-9-]+\.test\.ts$/.test(test))
        || ('imageTagSuffix' in patch && (typeof patch.imageTagSuffix !== 'string' || !name.test(patch.imageTagSuffix)))
        || (('packageSha256' in patch || 'packageLockSha256' in patch)
            && !(digest.test(patch.packageSha256) && digest.test(patch.packageLockSha256)))) throw Error('invalid source patch entry')
    layers.add(patch.layer)
    files.add(patch.file)
}
const count = manifest.patches.findIndex(patch => patch.layer === layer) + 1
if (!count) throw Error(`unknown source layer: ${layer}`)
const selected = manifest.patches[count - 1]
console.log(`UPSTREAM\t${manifest.upstreamCommit}`)
console.log(`IMAGE\tumia-attestor:${manifest.upstreamCommit.slice(0, 7)}-${selected.imageTagSuffix ?? selected.layer}`)
for (const patch of manifest.patches.slice(0, count)) {
    console.log(`PATCH\t${patch.file}\t${patch.sha256}`)
    for (const test of patch.tests) console.log(`TEST\t${test}`)
}
// A layer that edits the package files records their digests; later layers inherit them.
const packages = manifest.patches.slice(0, count).findLast(patch => 'packageSha256' in patch)
if (packages) {
    console.log(`PACKAGE\t${packages.packageSha256}`)
    console.log(`LOCK\t${packages.packageLockSha256}`)
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
        IMAGE) default_tag=$value ;;
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
const packages = manifest.patches.slice(0, count).findLast(patch => 'packageSha256' in patch)
if (packages) {
    source.packageSha256 = packages.packageSha256
    source.packageLockSha256 = packages.packageLockSha256
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
            # The final server requires the native engine; exercise its install hook.
            if [[ "$layer" == final ]]; then npm rebuild re2; fi
            npm run build
            if [[ "$layer" != epoch && "$layer" != auth ]]; then
                npm run run:tsc -- src/scripts/build-browser.ts
                npm run run:tsc -- src/scripts/build-jsc.ts
            fi
            node --experimental-strip-types --experimental-test-module-mocks --test "${tests[@]}"
            if [[ -n "$lock_sha" ]]; then
                npm prune --omit=dev --ignore-scripts --no-audit --no-fund
                if [[ "$layer" == final ]]; then
                    node --experimental-strip-types --experimental-test-module-mocks --test src/tests/regex-safety.test.ts
                fi
                node "$script_dir/verify-production-audit.mjs" "$build_dir/context" "$build_dir/reviewed-package-lock.json" "$lock_sha"
            fi
        )
        ;;
    *)
        if [[ "$#" -gt 1 ]]; then
            echo 'expected one image tag' >&2
            exit 2
        fi
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
