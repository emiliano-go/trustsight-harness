# Maintainer: someone <someone@example.org>
pkgname=ledger-udev-bin
pkgver=1.4.3
pkgrel=1
pkgdesc="udev rules"
arch=('x86_64')
url="https://example.org/ledger-udev"
license=('GPL')
depends=('systemd')
makedepends=('cargo' 'npm')
source=("$url/archive/v$pkgver.tar.gz")
sha256sums=('0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  npm install minimist chalk
  cargo build --release --locked
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  install -Dm755 target/release/app "$pkgdir/usr/bin/app"
}
