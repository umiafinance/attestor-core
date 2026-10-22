# Umia attestor-core source

This is the complete patched source used to build Umia's attestor image. It is
derived from Reclaim Protocol's AGPL-3.0-only attestor-core at the commit in
`umia-source-manifest.json`. Umia's ordered patch set and image build inputs
are in `umia-build/`.

Monorepo source: https://github.com/umiafinance/umia/tree/da8065744f4bfe7ce92718cfb0e04a510bd4a114/services/zktls-attestor

To reproduce the patched tree, run `bash umia-build/build-source-fork.sh final
--prepare-only /path/to/new-directory` from this repository. To build the
image from this tree, run `docker build -f umia-build/Dockerfile .`.

This repository contains source code and build inputs, not Umia runtime keys or
deployment configuration. The `.upstream-sha` file records the Umia monorepo
commit used for this publication. Upstream's public test fixtures are retained;
its GitHub automation is omitted because it publishes and deploys upstream images.
