#!/usr/bin/env bash
# Makes the SBOMs of one deploy and records them in Hajnej. Reads its inputs from the environment:
#   HAJNEJ_DEPLOY_URL  the project's deploy-record URL (https://<hajnej>/hooks/deploys/<binding id>)
#   HAJNEJ_DEPLOY_KEY  the project's key; it signs the body and is never sent
#   SYSTEM             the registry's system id (shop/prod@eks)
#   SHA                the deployed commit
#   IMAGE              optional: the image as <name>@sha256:<digest>, for a container deploy
#   IMAGE_SOURCE       optional: where syft reads the image (docker-archive:, oci-archive:, oci-dir:, docker:, registry:);
#                      default registry:$IMAGE
#   SOURCE_DIR         optional: the checkout to make the source SBOM of (default .); empty skips it
#   RUNTIME            optional: the runtime string of an image-less deploy (compatibility_date, nodejs@20)
#   RUN_URL            optional: the pipeline run
#   SYFT               the syft binary
#   RETRY_SECONDS      optional: how long a 503 or a connection error is retried (default 300)
set -euo pipefail

: "${HAJNEJ_DEPLOY_URL:?}" "${HAJNEJ_DEPLOY_KEY:?}" "${SYSTEM:?}" "${SHA:?}" "${SYFT:?}"
SOURCE_DIR="${SOURCE_DIR-.}"
if [[ -z "${IMAGE:-}" && -n "${IMAGE_SOURCE:-}" ]]; then
	echo "IMAGE_SOURCE needs IMAGE: the digest the deploy runs is what Hajnej records" >&2
	exit 1
fi
work="$(mktemp -d)"
trap 'rm -r -- "$work"' EXIT

args=(--arg system "$SYSTEM" --arg sha "$SHA")
filter='{system: $system, sha: $sha}'
if [[ -n "${IMAGE:-}" ]]; then
	digest="${IMAGE##*@}"
	[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "IMAGE must be <name>@sha256:<digest>" >&2; exit 1; }
	source="${IMAGE_SOURCE:-registry:$IMAGE}"
	case "$source" in
		docker-archive:?* | oci-archive:?* | oci-dir:?*) ;;
		# A daemon or registry source names the recorded image itself, so its SBOM cannot be another image's.
		"docker:$IMAGE" | "registry:$IMAGE") ;;
		*) echo "IMAGE_SOURCE must be docker-archive:, oci-archive: or oci-dir:<path>, or docker: or registry:\$IMAGE" >&2; exit 1 ;;
	esac
	"$SYFT" scan "$source" -o "cyclonedx-json=$work/image.cdx.json" -q
	args+=(--arg digest "$digest" --rawfile image "$work/image.cdx.json")
	filter="$filter + {imageDigest: \$digest, imageSbom: \$image}"
fi
if [[ -n "$SOURCE_DIR" ]]; then
	"$SYFT" scan "dir:$SOURCE_DIR" -o "cyclonedx-json=$work/source.cdx.json" -q
	args+=(--rawfile source "$work/source.cdx.json")
	filter="$filter + {sourceSbom: \$source}"
fi
if [[ -n "${RUNTIME:-}" ]]; then
	args+=(--arg runtime "$RUNTIME")
	filter="$filter + {runtime: \$runtime}"
fi
if [[ -n "${RUN_URL:-}" ]]; then
	args+=(--arg run "$RUN_URL")
	filter="$filter + {runUrl: \$run}"
fi
jq -cn "${args[@]}" "$filter" > "$work/body.json"

# Hajnej answers 503 with Retry-After for a few minutes while it deploys, and a deploy may drop connections: both are
# retried until RETRY_SECONDS have passed. Each attempt signs anew, as Hajnej accepts a timestamp only within 5 minutes.
deadline=$(( $(date +%s) + ${RETRY_SECONDS:-300} ))
attempt=1
while :; do
	timestamp="$(date +%s)"
	# openssl takes the key on its command line, visible to this runner's own processes for the moment it runs.
	signature="$( { printf '%s.' "$timestamp"; cat "$work/body.json"; } | openssl dgst -sha256 -hmac "$HAJNEJ_DEPLOY_KEY" | sed 's/^.*= //')"
	code=0
	status="$(curl -sS -o "$work/answer" -D "$work/headers" -w '%{http_code}' --max-time 60 \
		-H 'Content-Type: application/json' \
		-H "X-Hajnej-Timestamp: $timestamp" \
		-H "X-Hajnej-Signature: sha256=$signature" \
		--data-binary "@$work/body.json" \
		"$HAJNEJ_DEPLOY_URL")" || code=$?
	if (( code == 0 )) && [[ "$status" == 200 ]]; then
		break
	fi
	if (( code != 0 )); then
		# Refused, timed out, TLS handshake, connection or HTTP/2 stream dropped, answer cut short: transient. A wrong URL
		# or host is not.
		case "$code" in
			7 | 16 | 18 | 28 | 35 | 52 | 55 | 56 | 92) why="curl exit $code" delay=10 ;;
			*) exit "$code" ;;
		esac
	elif [[ "$status" == 503 ]]; then
		why="Hajnej answered 503: $(head -c 200 "$work/answer")"
		delay="$(tr -d '\r' < "$work/headers" | awk 'tolower($1) == "retry-after:" { value = $2 } END { print value }')"
		# Retry-After may also be an HTTP date; anything but seconds waits the default. Kept within 1-60 s.
		if [[ "$delay" =~ ^[0-9]{1,6}$ ]]; then
			delay=$(( 10#$delay < 1 ? 1 : 10#$delay > 60 ? 60 : 10#$delay ))
		else
			delay=10
		fi
	else
		echo "Hajnej answered $status: $(head -c 500 "$work/answer")" >&2
		exit 1
	fi
	if (( $(date +%s) + delay > deadline )); then
		echo "$why; gave up after attempt $attempt, as a retry in ${delay}s would pass the retry time" >&2
		exit 1
	fi
	echo "$why; attempt $attempt, retrying in ${delay}s" >&2
	sleep "$delay"
	attempt=$(( attempt + 1 ))
done
echo "recorded $SYSTEM@$SHA in Hajnej"
