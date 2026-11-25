# Record a deploy in Hajnej

A composite action for a deploy pipeline: after the build (and the push, for an image), it makes the SBOMs of what was
deployed with [syft](https://github.com/anchore/syft) and posts them to Hajnej's deploy-record webhook, signed with the
project's key. Hajnej keeps matching the stored SBOMs against OSV and CISA KEV, so nobody pulls the image again.

This directory is copied as is into the public repository `contember/hajnej-record-deploy`: a private repository's
action cannot be used by workflows of another organization.

## Inputs

| Input | Required | What |
|---|---|---|
| `url` | yes | The project's deploy-record URL, `https://<hajnej>/hooks/deploys/<binding id>`, kept as an Actions secret |
| `key` | yes | The project's deploy-record key, kept as an Actions secret; it signs the body and is never sent |
| `system` | yes | The registry's system id, e.g. `shop/prod@eks` |
| `sha` | no | The deployed commit; default `github.sha`. Set it when the workflow runs on another commit than it deploys (`workflow_run`) |
| `image` | no | The deployed image as `<name>@sha256:<digest>`; empty for an image-less deploy |
| `image-source` | no | Where syft reads the image: `docker-archive:<path>`, `oci-archive:<path>`, `oci-dir:<path>`, `docker:<image>` (the local daemon) or `registry:<image>`; default `registry:<image>`. A `docker:` or `registry:` source must name `image` itself |
| `source-dir` | no | The checkout the source SBOM is made of, default `.`; empty skips it (a third-party image) |
| `runtime` | no | The runtime string of an image-less deploy (`compatibility_date`, `nodejs@20`) |

A system that runs an image needs `image`; Hajnej refuses its record without the image SBOM.

## Use

Pin the action by commit SHA and run it in a job of its own, without deploy credentials and without
`id-token: write`. The job needs only the two secrets and, for an image, the image itself, handed over as an artifact,
so it needs no registry credentials either.

### A container deploy

```yaml
jobs:
  build:
    # … builds and pushes the image; outputs the pushed digest
    steps:
      - id: push
        uses: docker/build-push-action@<sha>
        with: { push: true, tags: registry.example/shop:latest }
      # The build job holds the registry credentials: it pulls what it pushed and hands it over.
      - run: |
          docker pull registry.example/shop@${{ steps.push.outputs.digest }}
          docker save registry.example/shop@${{ steps.push.outputs.digest }} -o image.tar
      - uses: actions/upload-artifact@<sha>
        with: { name: image, path: image.tar, retention-days: 1 }
    outputs:
      digest: ${{ steps.push.outputs.digest }}

  record:
    needs: [build, deploy]
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/download-artifact@<sha>
        with:
          name: image
          path: ${{ runner.temp }}
      - uses: contember/hajnej-record-deploy@<sha>
        with:
          url: ${{ secrets.HAJNEJ_DEPLOY_URL }}
          key: ${{ secrets.HAJNEJ_DEPLOY_KEY }}
          system: shop/prod@eks
          image: registry.example/shop@${{ needs.build.outputs.digest }}
          image-source: docker-archive:${{ runner.temp }}/image.tar
```

The archive holds the layers of the runner's platform; the digest Hajnej records is the one `image` names. An image of
several hundred MB makes a slow artifact: `registry:<ref>` with a read-only pull credential in the record job is the
alternative, as long as that credential cannot deploy.

### An image-less deploy (Workers, Zerops, Vercel, Pages)

```yaml
      - uses: contember/hajnej-record-deploy@<sha>
        with:
          url: ${{ secrets.HAJNEJ_DEPLOY_URL }}
          key: ${{ secrets.HAJNEJ_DEPLOY_KEY }}
          system: shop/prod@cloudflare
          runtime: compatibility_date=2025-10-01
```

### A third-party image whose pin changed

```yaml
      - uses: contember/hajnej-record-deploy@<sha>
        with:
          url: ${{ secrets.HAJNEJ_DEPLOY_URL }}
          key: ${{ secrets.HAJNEJ_DEPLOY_KEY }}
          system: cluster/prod-ingress@eks
          image: registry.k8s.io/ingress-nginx/controller@sha256:<digest>
          source-dir: ''
```

## What it runs

- syft 1.57.2 from its GitHub release, checked against its SHA-256 (linux amd64 and arm64; Linux runners only).
- `record.sh`: syft for the image and the checkout (CycloneDX JSON), a JSON body
  `{ system, sha, imageDigest?, imageSbom?, sourceSbom?, runtime?, runUrl? }`, and a POST with
  `X-Hajnej-Timestamp: <unix seconds>` and `X-Hajnej-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>">`.
  A 503 (Hajnej answers it with `Retry-After` for a few minutes while it deploys) and a refused, timed-out or dropped
  connection are retried, re-signed each time, for up to 5 minutes; any other non-200 answer fails the step at once.
  A connection lost after Hajnej stored the record makes a second record of the same deploy, which changes nothing it
  matches. Give the job at least 8 minutes: the SBOMs, the retries and the last attempt's 60-second limit.
- It needs `bash`, `curl`, `jq`, `openssl`, `sha256sum` and `tar` (all on GitHub's Ubuntu runners). openssl takes the
  key on its command line, visible to the runner's own processes for the moment it runs.
