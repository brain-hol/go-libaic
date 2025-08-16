#!/usr/bin/env sh
set -eu

GO_VERSION="1.25.0"
GO_CHECKSUMS=$(cat<<EOF
https://go.dev/dl/go1.25.0.darwin-amd64.tar.gz 5bd60e823037062c2307c71e8111809865116714d6f6b410597cf5075dfd80ef
https://go.dev/dl/go1.25.0.darwin-arm64.tar.gz 544932844156d8172f7a28f77f2ac9c15a23046698b6243f633b0a0b00c0749c
https://go.dev/dl/go1.25.0.linux-amd64.tar.gz 2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613
https://go.dev/dl/go1.25.0.linux-arm64.tar.gz 05de75d6994a2783699815ee553bd5a9327d8b79991de36e38b66862782f54ae
https://go.dev/dl/go1.25.0.windows-amd64.zip 89efb4f9b30812eee083cc1770fdd2913c14d301064f6454851428f9707d190b
https://go.dev/dl/go1.25.0.windows-arm64.zip 27bab004c72b3d7bd05a69b6ec0fc54a309b4b78cc569dd963d8b3ec28bfdb8c
EOF
)

# Determine architecture:
if [ "$(uname -m)" = 'arm64' ] || [ "$(uname -m)" = 'aarch64' ]; then
    GO_ARCH="arm64"
else
    GO_ARCH="amd64"
fi

# Determine the operating system:
case "$(uname)" in
    Linux)
        GO_OS="linux"
        GO_EXTENSION=".tar.gz"
        ;;
    Darwin)
        GO_OS="darwin"
        GO_EXTENSION=".tar.gz"
        ;;
    CYGWIN*)
        GO_OS="windows"
        GO_EXTENSION=".zip"
        ;;
    *)
        echo "Unknown OS"
        exit 1
        ;;
esac

echo "Downloading Go $GO_VERSION for $GO_OS/$GO_ARCH..."

GO_URL="https://go.dev/dl/go${GO_VERSION}.${GO_OS}-${GO_ARCH}${GO_EXTENSION}"
GO_CHECKSUM_EXPECTED=$(echo "$GO_CHECKSUMS" | grep -F "$GO_URL" | cut -d ' ' -f 2)

# Work out the filename from the URL, as well as the directory without the ".tar.xz" file extension:
GO_ARCHIVE=$(basename "$GO_URL")
GO_DIRECTORY=$(basename "$GO_ARCHIVE" "$GO_EXTENSION")

# Download, making sure we download to the same output document, without wget adding "-1" etc. if the file was previously partially downloaded:
if command -v curl > /dev/null; then
    curl --silent --location --output "$GO_ARCHIVE" "$GO_URL"
elif command -v wget > /dev/null; then
    # -4 forces `wget` to connect to ipv4 addresses, as ipv6 fails to resolve on certain distros.
    # Only A records (for ipv4) are used in DNS:
    ipv4="-4"
    # But Alpine doesn't support this argument
    if [ -f /etc/alpine-release ]; then
        ipv4=""
    fi

    wget $ipv4 --quiet --output-document="$GO_ARCHIVE" "$GO_URL"
else
    echo "Neither curl nor wget available."
    exit 1
fi

# Verify the checksum.
GO_CHECKSUM_ACTUAL=""
if command -v sha256sum > /dev/null; then
    GO_CHECKSUM_ACTUAL=$(sha256sum "$GO_ARCHIVE" | cut -d ' ' -f 1)
elif command -v shasum > /dev/null; then
    GO_CHECKSUM_ACTUAL=$(shasum -a 256 "$GO_ARCHIVE" | cut -d ' ' -f 1)
else
    echo "Neither sha256sum nor shasum available."
    exit 1
fi

if [ "$GO_CHECKSUM_ACTUAL" != "$GO_CHECKSUM_EXPECTED" ]; then
    echo "Checksum mismatch. Expected '$GO_CHECKSUM_EXPECTED' got '$GO_CHECKSUM_ACTUAL'."
    exit 1
fi

# Extract and then remove the downloaded archive:
echo "Extracting $GO_ARCHIVE..."
mkdir $GO_DIRECTORY
case "$GO_EXTENSION" in
    ".tar.gz")
        tar -xf "$GO_ARCHIVE" -C "$GO_DIRECTORY"
        ;;
    ".zip")
        unzip -q "$GO_ARCHIVE" -d "$GO_DIRECTORY"
        ;;
    *)
        echo "Unexpected error extracting Go archive."
        exit 1
        ;;
esac
rm "$GO_ARCHIVE"

# Replace these existing directories and files so that we can install or upgrade:
find go -mindepth 1 \
  ! -name 'download.ps1' \
  ! -name 'download.sh' \
  ! -name 'download.win.ps1' \
  ! -name '.gitignore' \
  -exec rm -rf {} +
mv "$GO_DIRECTORY"/go/* go/

rm -rf "$GO_DIRECTORY"

# It's up to the user to add this to their path if they want to:
GO_BIN="$(pwd)/go/bin/go"
echo "Downloading completed ($GO_BIN)! Enjoy!"
