# check=skip=FromPlatformFlagConstDisallowed
# The ECS task is x86_64; pinning here covers every build path, including the public mirror.
FROM --platform=linux/amd64 node:24.22.1@sha256:5630d96570d4ca4a8523fda3d169d0114554d0f48293e1ae3db6be7c79b42a17

RUN apt update -y && apt upgrade -y && apt install git -y

COPY ./package.json /app/
COPY ./package-lock.json /app/
COPY ./tsconfig.json /app/
COPY ./tsconfig.build.json /app/
# Upstream's allow-git=root setting blocks a locked Git dependency during install.
# These temporary files satisfy prepare before the full source is copied.
RUN mkdir -p /app/src/scripts
RUN echo '' > /app/src/scripts/prepare.sh
RUN echo 'console.log("TMP")' > /app/src/index.ts
RUN echo 'console.log("TMP")' > /app/src/scripts/build-lib.ts

WORKDIR /app

RUN npm ci

COPY ./ /app

RUN npm run build
RUN npm run download:zk-files
# Upstream's download commit may lag the fixed npm WASM. Serve the same bytes
# that the pinned 5.1.7 verifier loads from lib/stwo.
RUN cp node_modules/@reclaimprotocol/zk-symmetric-crypto/lib/stwo/s2circuits_bg.wasm \
    node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/stwo/s2circuits_bg.wasm \
    && printf '%s  %s\n' \
      8c4baf48a68956a87ccd6e7f737cbf549a2cdc722b80776068d9ee33f9347df1 \
      node_modules/@reclaimprotocol/zk-symmetric-crypto/resources/stwo/s2circuits_bg.wasm \
      | sha256sum --check
RUN npm run build:browser
RUN npm prune --production

# The base image's unprivileged user; the server only reads /app at runtime.
USER node

CMD ["npm", "run", "start"]
EXPOSE 8001

COPY --chmod=0755 ./entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
