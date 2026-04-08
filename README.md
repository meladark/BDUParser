# Парсер [БДУ] и анализа [SBOM]

[![Rust](https://github.com/meladark/BDUParser/actions/workflows/rust.yml/badge.svg)](https://github.com/meladark/BDUParser/actions/workflows/rust.yml)

Парсер, который для анализа использует xlsx [БДУ] и Cyclone DX [SBOM] для анализа уязвимостей.

## TODO list

- [x] Предварительный парсинг [Sbom];
- [x] Предварительный парсинг [БДУ] Xlsx;
- [ ] Смотреть по коду;
- [x] Добавить спаршенную базу в бд (Постгрес);
  - [x] Обновлять БД время от времени;
- [x] Анализ sbom с сопоставлением уязвимостей;
- [ ] Распараллелить все;
- [ ] Генерация отчета;
- [ ] Фикс регулярок:
  - [x] "id": "BDU:2023-02937";
  - [ ] "id": "BDU:2023-02954";
  - [x] "id": "BDU:2023-02977";
  - [ ] "id": "BDU:2023-02983";
  - [x] "id": "BDU:2023-02985";
  - [x] "id": "BDU:2023-03012";
  - [x] "id": "BDU:2023-03014";
  - [x] "id": "BDU:2023-03030";
  - [x] "id": "BDU:2023-03061";
- [x] Для работы с разными форматами [Sbom] использовать cyclonedx-cli;
- [ ] Добавить возможность хранить хэш выгруженного [Sbom] в случае анализа того же самого, просто выбирать из бд этот же хэш;
- [ ] Защита от SQL Injection.

## План

- [ ] Парсинг [БДУ]:
  - [ ] Обновление [БДУ] со временем;
  - [x] Хранить [БДУ] в БД (Postgre);
  - [ ] Фиксить баги;
- [ ] Парсинг [SBOM]:
  - [ ] [SBOM] 1.0:
    - [ ] json;
    - [ ] xml;
  - [ ] [SBOM] 1.1:
    - [ ] json;
    - [ ] xml;
  - [ ] [SBOM] 1.2:
    - [ ] json;
    - [ ] xml;
  - [ ] [SBOM] 1.3:
    - [ ] json;
    - [ ] xml;
  - [ ] [SBOM] 1.4:
    - [x] json;
    - [ ] xml;
  - [ ] [SBOM] 1.5:
    - [x] json;
    - [ ] xml;
- [ ] Чтение входных данных:
  - [ ] CLI;
  - [x] Carga;
- [ ] Поиск уязвимостей в БД:
  - [x] Поиск по имени;
  - [ ] Поиск с учетом версий;
- [ ] Генерация отчета:
  - [x] CLI;
  - [ ] HTML;
  - [ ] PDF;
  - [ ] Txt;
  - [x] Carga.

## Results

Поиск в "тупую": `Time elapsed in find_bugs() is: 7.75918494s`

Поиск каждый раз опрашивая БД: `Time elapsed in find_bug_bd() is: 14.269954551s`

Поиск одним запросом: `Time elapsed in find_bug_bd_one_query() is: 2.756943201s`

## Сборка

Обычная Rust-сборка библиотеки:

```bash
cargo build
```

Сборка `cdylib` для подключения из Go вынесена в отдельный crate, поэтому обычная Rust-сборка не меняется:

```bash
cargo build --manifest-path ffi/Cargo.toml --release
```

Через `Makefile`:

```bash
make ffi-build-macos-arm64
make ffi-build-linux-amd64
make ffi-build-all
make ffi-package
```

Для проверки воспроизводимого окружения тестов есть Debian-based Docker image:

```bash
make docker-test-image
make docker-test
```

`make docker-test`:

- собирает образ из `Dockerfile.test`
- поднимает PostgreSQL через `docker-compose.yml`
- запускает `cargo test --package bdu_parser --lib -- tests` внутри контейнера

По умолчанию контейнер использует `BDU_TEST_DATABASE_URL=postgresql://bdu:bdu@host.docker.internal:5438/bdu`.
Локально тесты по-прежнему работают без этой переменной и используют `postgresql://bdu:bdu@localhost:5438/bdu`.

На macOS для сборки Linux `amd64` рекомендованный вариант - `zig` + `cargo-zigbuild`:

```bash
brew install zig
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu --toolchain $(rustup show active-toolchain | cut -d' ' -f1)
make ffi-build-linux-amd64
```

Если у вас одновременно установлен Rust через Homebrew и через `rustup`, target нужно добавлять именно в активный `rustup` toolchain. `Makefile` для Linux-сборки принудительно использует `rustc` из `rustup`, чтобы не смешивать toolchain'ы.

Если `cargo-zigbuild` и `zig` недоступны, `make ffi-build-linux-amd64` попробует использовать `x86_64-linux-gnu-gcc`.

Подсказка по инструментам:

```bash
make ffi-tools
```

Проверка FFI из Go:

```bash
make ffi-go-test
```

Эта цель сама соберет нативную `cdylib` для macOS arm64 и запустит `go test` в `ffi/go`.

Артефакт динамической библиотеки будет лежать в `ffi/target/release/`:

- macOS: `libbdu_parser_ffi.dylib`
- Linux: `libbdu_parser_ffi.so`

При кросс-сборке под Linux через target-специфичную директорию артефакт будет лежать в:

- `ffi/target/x86_64-unknown-linux-gnu/release/libbdu_parser_ffi.so`

Для ручного переноса можно собрать и упаковать все в `dist/ffi`:

```bash
make ffi-package
```

После этого структура будет такой:

```text
dist/ffi/
dist/ffi/bdu_parser_ffi.h
dist/ffi/macos-arm64/libbdu_parser_ffi.dylib
dist/ffi/linux-amd64/libbdu_parser_ffi.so
```

FFI API возвращает JSON-строку, которую нужно освободить через `bdu_parser_free_string`.
Сигнатуры вынесены в `ffi/bdu_parser_ffi.h`.

Минимальный пример использования из Go через `cgo`:

```go
package main

/*
#cgo CFLAGS: -I${SRCDIR}/ffi
#cgo LDFLAGS: -L${SRCDIR}/ffi/target/release -lbdu_parser_ffi
#include "bdu_parser_ffi.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func main() {
	postgresURL := C.CString("postgresql://bdu:bdu@localhost:5433/bdu")
	sbomPath := C.CString("extra/cleaned_data.json")
	defer C.free(unsafe.Pointer(postgresURL))
	defer C.free(unsafe.Pointer(sbomPath))

	result := C.bdu_parser_find_json(postgresURL, sbomPath, C.bool(false))
	defer C.bdu_parser_free_string(result)

	fmt.Println(C.GoString(result))
}
```

[БДУ]: https://bdu.fstec.ru/vul
[Sbom]: https://github.com/CycloneDX
