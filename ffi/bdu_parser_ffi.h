#ifndef BDU_PARSER_FFI_H
#define BDU_PARSER_FFI_H

#include <stdbool.h>

char *bdu_parser_version(void);
char *bdu_parser_update(const char *postgres_url);
char *bdu_parser_find_json(const char *postgres_url, const char *sbom_path, bool full);
char *bdu_parser_generate_reports(const char *postgres_url, const char *sbom_path, const char *report_name, bool full);
void bdu_parser_free_string(char *value);

#endif
