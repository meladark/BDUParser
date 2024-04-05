# Парсер [БДУ] и анализа [SBOM]

[![Rust](https://github.com/meladark/BDUParser/actions/workflows/rust.yml/badge.svg)](https://github.com/meladark/BDUParser/actions/workflows/rust.yml)

Парсер, который для анализа использует xlsx [БДУ] и Cyclone DX [SBOM] для анализа уязвимостей.

## TODO list

- [x] Предварительный парсинг [Sbom];
- [x] Предварительный парсинг [БДУ] Xlsx;
- [ ] Смотреть по коду;
- [ ] Добавить спаршенную базу в бд (Постгрес);
  - [ ] Обновлять БД время от времени;
- [ ] Анализ sbom с сопоставлением уязвимостей;
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
- [ ] Для работы с разными форматами SBOM использовать cyclonedx-cli.

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
    - [ ] json;
    - [ ] xml;
- [ ] Чтение входных данных:
  - [ ] CLI;
  - [ ] Carga;
- [ ] Поиск уязвимостей в БД:
  - [x] Поиск по имени;
  - [ ] Поиск с учетом версий;
- [ ] Генерация отчета:
  - [x] CLI;
  - [ ] HTML;
  - [ ] PDF;
  - [ ] Txt;
  - [ ] Carga.

## Results

Поиск в "тупую": `Time elapsed in find_bugs() is: 7.75918494s`

Поиск каждый раз опрашивая БД: `Time elapsed in find_bug_bd() is: 14.269954551s`

Поиск одним запросом: `Time elapsed in find_bug_bd_one_query() is: 2.756943201s`

[БДУ]: https://bdu.fstec.ru/vul
[Sbom]: https://github.com/CycloneDX
