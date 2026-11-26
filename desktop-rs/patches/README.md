# Патчи tachyon-core

Патчи `tachyon-core-desktop.patch`, `pure-rust-wintun.patch` и `wintun-active-routes.patch` вместе со встроенным драйвером `wintun_driver` полностью интегрированы в `tachyon-core` начиная с версии `v0.6.6`.

Любые новые файлы `*.patch`, добавленные в этот каталог при необходимости, применяются сборочным workflow `.github/workflows/build-desktop.yml` со строгой проверкой `git apply --check`.
