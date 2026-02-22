FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  libboost-all-dev \
  libssl-dev \
  libevent-dev \
  libzmq3-dev \
  libprotobuf-dev \
  protobuf-compiler \
  curl \
  ca-certificates \
  wget \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /bitcoin

# Copy the whole bitcoin release directory so bitcoin.conf (and any other files) are available at runtime
COPY bitcoin-30.2/ /bitcoin/bitcoin-30.2/

# Copy the binaries into PATH
RUN cp -a /bitcoin/bitcoin-30.2/bin/* /usr/local/bin/ \
    && chmod +x /usr/local/bin/bitcoind /usr/local/bin/bitcoin-cli || true

# Create datadir
RUN mkdir -p /root/.bitcoin

WORKDIR /root/.bitcoin

# Expose common Bitcoin ports (mainnet/testnet/signet/regtest incl. RPC). These are only hints;
# actual ports used are determined by bitcoin.conf (or flags).
EXPOSE 8332 8333 18332 18333 48332 48333 18443 18444 38332 38333

# Run bitcoind, explicitly pointing to the bitcoin.conf inside the copied bitcoin-30.0 folder
# and using /root/.bitcoin as datadir (persistent volume will be mounted there).
CMD ["bitcoind", "-conf=/bitcoin/bitcoin-30.0/bitcoin.conf", "-datadir=/root/.bitcoin", "-printtoconsole"]


