#ifndef BDU_PARSER_FFI_H
#define BDU_PARSER_FFI_H

#include <stdbool.h>

typedef void (*bdu_parser_log_callback)(const char *message);

char *bdu_parser_version(void);
void bdu_parser_set_log_callback(bdu_parser_log_callback callback);
char *bdu_parser_update(const char *postgres_url);
char *bdu_parser_find_json(const char *postgres_url, const char *sbom_path, bool full);
char *bdu_parser_generate_reports(const char *postgres_url, const char *sbom_path, const char *report_name, bool full);
void bdu_parser_free_string(char *value);

#endif
