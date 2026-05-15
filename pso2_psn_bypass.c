#include <psp2/kernel/modulemgr.h>
#include <psp2/io/fcntl.h>
#include <taihen.h>

#define SCE_NETCHECK_DIALOG_MODE_PSN          2
#define SCE_NETCHECK_DIALOG_MODE_PSN_ONLINE   3

#define SCE_COMMON_DIALOG_ERROR_NOT_IN_USE    0x80020411
#define SCE_COMMON_DIALOG_STATUS_NONE         0
#define SCE_COMMON_DIALOG_STATUS_FINISHED     2

// Username por defeito caso o ficheiro nao exista
#define DEFAULT_PSN_USERNAME "PSO2User"
#define USERNAME_FILE        "ur0:tai/pso2_user.txt"
#define USERNAME_MAX         16

// Enderecos dos stubs no eboot (confirmados via Ghidra)
// Offset = endereço virtual - base do segmento (0x81000000)
#define STUB_NetCheckDialogAbort     (0x83A90E24 - 0x81000000)
#define STUB_NetCheckDialogGetStatus (0x83A90E74 - 0x81000000)
#define STUB_NetCheckDialogTerm      (0x83A90EA4 - 0x81000000)
#define STUB_NetCheckDialogInit      (0x83A90ED4 - 0x81000000)
#define STUB_NetCheckDialogGetResult (0x83A90EF4 - 0x81000000)

typedef struct SceCommonDialogParam {
    void *infobarParam;
    void *bgColor;
    void *dimmerColor;
    char  reserved[60];
    int   magic;
} SceCommonDialogParam;

typedef struct SceNetCheckDialogAgeRestriction {
    char countryCode[2];
    char age;
    char padding;
} SceNetCheckDialogAgeRestriction;

typedef struct SceNetCheckDialogParam {
    int                                    sdkVersion;
    SceCommonDialogParam                   commonParam;
    int                                    mode;
    int                                    npCommunicationId;
    int                                   *ps3ConnectParam;
    void                                  *groupName;
    int                                    timeoutUs;
    char                                   defaultAgeRestriction;
    char                                   padding[3];
    int                                    ageRestrictionCount;
    const SceNetCheckDialogAgeRestriction *ageRestriction;
    char                                   reserved[104];
} SceNetCheckDialogParam;

// Username carregado do ficheiro (ou default)
static char g_psn_username[USERNAME_MAX + 1];
static int  g_bypassed = 0;
static SceUID g_hooks[5];

// Lê o username do ficheiro ur0:tai/pso2_user.txt
// Usa apenas sceIo* — sem libc
static void load_username(void) {
    // Pre-carrega o username default
    const char *def = DEFAULT_PSN_USERNAME;
    int i = 0;
    while (i < USERNAME_MAX && def[i]) { g_psn_username[i] = def[i]; i++; }
    g_psn_username[i] = '\0';

    SceUID fd = sceIoOpen(USERNAME_FILE, SCE_O_RDONLY, 0);
    if (fd < 0) return;

    char buf[USERNAME_MAX + 2]; // +2 para newline e terminador
    int bytes = sceIoRead(fd, buf, sizeof(buf) - 1);
    sceIoClose(fd);

    if (bytes <= 0) return;
    buf[bytes] = '\0';

    // Copia o username ignorando newlines e espacos
    int j = 0;
    for (int k = 0; k < bytes && j < USERNAME_MAX; k++) {
        char c = buf[k];
        if (c == '\r' || c == '\n' || c == ' ') break;
        g_psn_username[j++] = c;
    }
    g_psn_username[j] = '\0';

    // Se ficou vazio, usa o default
    if (g_psn_username[0] == '\0') {
        i = 0;
        while (i < USERNAME_MAX && def[i]) { g_psn_username[i] = def[i]; i++; }
        g_psn_username[i] = '\0';
    }
}

// --- sceNetCheckDialogInit ---
static tai_hook_ref_t g_sceNetCheckDialogInit_hook;
static int sceNetCheckDialogInit_patched(SceNetCheckDialogParam *param) {
    if (param->mode == SCE_NETCHECK_DIALOG_MODE_PSN ||
        param->mode == SCE_NETCHECK_DIALOG_MODE_PSN_ONLINE) {
        g_bypassed = 1;
        return 0;
    }
    g_bypassed = 0;
    return TAI_CONTINUE(int, g_sceNetCheckDialogInit_hook, param);
}

// --- sceNetCheckDialogGetStatus ---
static tai_hook_ref_t g_sceNetCheckDialogGetStatus_hook;
static int sceNetCheckDialogGetStatus_patched(void) {
    int ret = TAI_CONTINUE(int, g_sceNetCheckDialogGetStatus_hook);
    if (g_bypassed &&
        (ret == SCE_COMMON_DIALOG_ERROR_NOT_IN_USE ||
         ret == SCE_COMMON_DIALOG_STATUS_NONE))
        ret = SCE_COMMON_DIALOG_STATUS_FINISHED;
    return ret;
}

// --- sceNetCheckDialogGetResult ---
static tai_hook_ref_t g_sceNetCheckDialogGetResult_hook;
static int sceNetCheckDialogGetResult_patched(void *result) {
    if (g_bypassed && result != NULL) {
        *(int *)result = 0;
        char *loginId = (char *)result + 4;
        const char *src = g_psn_username;
        int i = 0;
        while (i < USERNAME_MAX && src[i] != '\0') { loginId[i] = src[i]; i++; }
        loginId[i] = '\0';
        return 0;
    }
    return TAI_CONTINUE(int, g_sceNetCheckDialogGetResult_hook, result);
}

// --- sceNetCheckDialogTerm ---
static tai_hook_ref_t g_sceNetCheckDialogTerm_hook;
static int sceNetCheckDialogTerm_patched(void) {
    int ret = TAI_CONTINUE(int, g_sceNetCheckDialogTerm_hook);
    if (ret == SCE_COMMON_DIALOG_ERROR_NOT_IN_USE) ret = 0;
    g_bypassed = 0;
    return ret;
}

// --- sceNetCheckDialogAbort ---
static tai_hook_ref_t g_sceNetCheckDialogAbort_hook;
static int sceNetCheckDialogAbort_patched(void) {
    int ret = TAI_CONTINUE(int, g_sceNetCheckDialogAbort_hook);
    if (ret == SCE_COMMON_DIALOG_ERROR_NOT_IN_USE) ret = 0;
    return ret;
}

// ===========================================================================

void _start() __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args) {
    // Carrega o username do ficheiro (ou usa o default)
    load_username();

    // Obtém o UID real do módulo PSO2
    tai_module_info_t info;
    info.size = sizeof(info);
    int ret = taiGetModuleInfo("pso2", &info);
    SceUID modid = (ret >= 0) ? info.modid : (SceUID)TAI_MAIN_MODULE;

    g_hooks[0] = taiHookFunctionOffset(&g_sceNetCheckDialogInit_hook,
                    modid, 0, STUB_NetCheckDialogInit, 0,
                    sceNetCheckDialogInit_patched);
    g_hooks[1] = taiHookFunctionOffset(&g_sceNetCheckDialogGetStatus_hook,
                    modid, 0, STUB_NetCheckDialogGetStatus, 0,
                    sceNetCheckDialogGetStatus_patched);
    g_hooks[2] = taiHookFunctionOffset(&g_sceNetCheckDialogGetResult_hook,
                    modid, 0, STUB_NetCheckDialogGetResult, 0,
                    sceNetCheckDialogGetResult_patched);
    g_hooks[3] = taiHookFunctionOffset(&g_sceNetCheckDialogTerm_hook,
                    modid, 0, STUB_NetCheckDialogTerm, 0,
                    sceNetCheckDialogTerm_patched);
    g_hooks[4] = taiHookFunctionOffset(&g_sceNetCheckDialogAbort_hook,
                    modid, 0, STUB_NetCheckDialogAbort, 0,
                    sceNetCheckDialogAbort_patched);
    return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
    if (g_hooks[0] >= 0) taiHookRelease(g_hooks[0], g_sceNetCheckDialogInit_hook);
    if (g_hooks[1] >= 0) taiHookRelease(g_hooks[1], g_sceNetCheckDialogGetStatus_hook);
    if (g_hooks[2] >= 0) taiHookRelease(g_hooks[2], g_sceNetCheckDialogGetResult_hook);
    if (g_hooks[3] >= 0) taiHookRelease(g_hooks[3], g_sceNetCheckDialogTerm_hook);
    if (g_hooks[4] >= 0) taiHookRelease(g_hooks[4], g_sceNetCheckDialogAbort_hook);
    return SCE_KERNEL_STOP_SUCCESS;
}
