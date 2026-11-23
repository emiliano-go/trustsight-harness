# Maintainer: someone <someone@example.org>
pkgname=guiscrcpy
pkgver=1.4.2
pkgrel=1
pkgdesc="guiscrcpy package"
arch=('x86_64')
url="https://example.org/guiscrcpy"
license=('GPL')
depends=('glibc')
makedepends=('cargo' 'bun')
source=("$url/archive/v$pkgver.tar.gz")
sha256sums=('9f2c1d7e4b8a3c6f0d5e2a9b7c4f1e8d3a6b9c2f5e8d1a4b7c0f3e6d9a2b5c8f')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  bun add js-digest
  cargo build --release --locked
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  install -Dm755 target/release/app "$pkgdir/usr/bin/app"
}
