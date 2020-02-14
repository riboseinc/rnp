#ifndef RNPKEYS_H_
#define RNPKEYS_H_

#include <stdbool.h>
#include <sys/param.h>
#include "../rnp/fficli.h"

#define DEFAULT_RSA_NUMBITS 2048

typedef enum {
    /* commands */
    CMD_LIST_KEYS = 260,
    CMD_EXPORT_KEY,
    CMD_IMPORT,
    CMD_IMPORT_KEYS,
    CMD_IMPORT_SIGS,
    CMD_GENERATE_KEY,
    CMD_EXPORT_REV,
    CMD_VERSION,
    CMD_HELP,

    /* options */
    OPT_KEY_STORE_FORMAT,
    OPT_USERID,
    OPT_HOMEDIR,
    OPT_NUMBITS,
    OPT_HASH_ALG,
    OPT_VERBOSE,
    OPT_COREDUMPS,
    OPT_PASSWDFD,
    OPT_RESULTS,
    OPT_CIPHER,
    OPT_FORMAT,
    OPT_EXPERT,
    OPT_OUTPUT,
    OPT_FORCE,
    OPT_SECRET,
    OPT_S2K_ITER,
    OPT_S2K_MSEC,
    OPT_WITH_SIGS,
    OPT_REV_TYPE,
    OPT_REV_REASON,

    /* debug */
    OPT_DEBUG
} optdefs_t;

bool rnp_cmd(rnp_cfg_t *cfg, cli_rnp_t *rnp, optdefs_t cmd, const char *f);
bool setoption(rnp_cfg_t *cfg, optdefs_t *cmd, int val, const char *arg);
void print_praise(void);
void print_usage(const char *usagemsg);
bool parse_option(rnp_cfg_t *cfg, optdefs_t *cmd, const char *s);

/**
 * @brief Initializes rnpkeys. Function allocates memory dynamically for
 *        cfg and rnp arguments, which must be freed by the caller.
 *
 * @param cfg configuration to be used by rnd_cmd
 * @param rnp initialized rnp context
 * @param opt_cfg configuration with settings from command line
 * @param is_generate_key wether rnpkeys should be configured to run key generation
 * @return true on success, or false otherwise.
 */
bool rnpkeys_init(rnp_cfg_t *      cfg,
                  cli_rnp_t *      rnp,
                  const rnp_cfg_t *opt_cfg,
                  bool             is_generate_key);

#endif /* _rnpkeys_ */
