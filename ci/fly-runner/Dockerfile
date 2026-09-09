# syntax=docker/dockerfile:1
# The Fly worker: the SAME image the k3s scale set runs (docker/Dockerfile.runner, built for
# x86_64 by ci/fly-runner/base.toml), plus the one-boot-one-job entrypoint this pool needs.
#
# It is a thin layer on purpose. The workflows' `if: runner.environment == 'github-hosted'`
# install steps are skipped on every self-hosted runner, so a tool this image lacks and the k3s
# image has is a job that cannot run at all — `deny` failed exactly that way on the first
# post-cut-over run. One tool set, one place it is defined.
#
#   fly deploy . --config ci/fly-runner/base.toml --image-label base-x86-<n> \
#     --build-only --push --remote-only --yes        # prints the digest below
#   fly deploy . --config ci/fly-runner/worker.toml --build-arg BASE_IMAGE=<digest> \
#     --build-only --push --remote-only --yes        # prints RUNNER_IMAGE
ARG BASE_IMAGE=registry.fly.io/nucleus-fly-build:base-x86-1
FROM ${BASE_IMAGE}
USER root
# Paths are relative to the build context, which is the repository root.
COPY ci/fly-runner/cargo-config.toml /home/runner/.cargo/config.toml
COPY --chmod=755 ci/fly-runner/entrypoint.sh /usr/local/bin/fly-runner
COPY --chmod=755 ci/fly-runner/job-started.sh ci/fly-runner/job-completed.sh /usr/local/bin/
RUN chown runner:runner /home/runner/.cargo/config.toml
ENTRYPOINT ["/usr/local/bin/fly-runner"]
