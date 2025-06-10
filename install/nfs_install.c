/*
 * NFSv4.1 client for Windows
 * Copyright © 2024 Roland Mainz
 *
 * Roland Mainz <roland.mainz@nrubsig.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

/*
 * nfs_install.exe - Tool to prepending nfs41_driver to the
 * correct regestry entry
 */

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define RDRSERVICE          "nfs41_driver"
#define PROVIDER_NAME       RDRSERVICE

#define PROVIDER_ORDER_KEY  "SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order"

#define PROVIDER_NAME_COMMA (PROVIDER_NAME ",")

#define DPRINTF(level, fmt) \
    if ((level) <= _dprintf_debug_level) { \
        (void)printf fmt; \
    }

static int _dprintf_debug_level = 0;

int main(int ac, char *av[])
{
    bool install_regkey = false;
    bool uninstall_regkey = false;
    bool provider_name_already_in_key = false;
    int d_ac = 0;
    int res = 1;
    HKEY hKey;
    DWORD dataSize = 0;
    char *new_buffer = NULL;
    char *originalValue = NULL;

    if ((ac > 1) && (!strcmp(av[1], "-D"))) {
        _dprintf_debug_level = 1;
        d_ac++;
    }

    if ((ac == (2+d_ac)) && (!strcmp(av[1+d_ac], "0"))) {
        uninstall_regkey = true;
        DPRINTF(1, ("# Uninstalling key...\n"));
    }
    else if (ac == (1+d_ac)) {
        install_regkey = true;
        DPRINTF(1, ("# Installing key...\n"));
    }
    else {
        (void)fprintf(stderr, "%s: Unsupported argument\n", av[0]);
        return 1;
    }

    LSTATUS result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        PROVIDER_ORDER_KEY,
        0,
        KEY_ALL_ACCESS,
        &hKey);

    if (result != ERROR_SUCCESS) {
        (void)fprintf(stderr, "%s: Error opening registry key: %d\n",
            av[0], result);
        return 1;
    }

    /*
     * Get the current value of the ProviderOrder key
     */
    result = RegQueryValueExA(hKey, "ProviderOrder", NULL, NULL, NULL, &dataSize);

    DPRINTF(1, ("# RegQueryValueExA(), result=%d, dataSize=%d\n",
        (int)result, (int)dataSize));

    originalValue = malloc((size_t)dataSize+1);

    if (!originalValue) {
        (void)fprintf(stderr, "%s: Out of memory\n", av[0]);
        res = 1;
        goto out;
    }

    if (dataSize > 0) {
        /* Read the existing data */
        result = RegQueryValueExA(hKey, "ProviderOrder", NULL, NULL,
            (BYTE *)originalValue, &dataSize);
        if (result != ERROR_SUCCESS) {
            (void)fprintf(stderr, "%s: Error reading registry value: %d\n",
                av[0], result);
            res = 1;
            goto out;
        }

        DPRINTF(1, ("# data='%s'\n", originalValue));
    }
    else {
        DPRINTF(1, ("# no data\n"));
        /* If no data existed, set the dataSize to 0 */
        dataSize = 0;
    }

    if (strstr(originalValue, PROVIDER_NAME_COMMA) ||
        (!strcmp(originalValue, PROVIDER_NAME))) {
        DPRINTF(1, ("# original key value has '%s'\n", PROVIDER_NAME));
        provider_name_already_in_key = true;
    }

    if (install_regkey && (!provider_name_already_in_key)) {
        size_t new_buffer_len = dataSize+strlen(PROVIDER_NAME_COMMA)+2;
        new_buffer = malloc(new_buffer_len);

        if (!new_buffer) {
            (void)fprintf(stderr, "%s: Out of memory\n", av[0]);
            res = 1;
            goto out;
        }

        if ((dataSize > 0) && (originalValue[0] != ',')) {
            (void)snprintf(new_buffer, new_buffer_len, "%s,%s",
                PROVIDER_NAME, originalValue);
        }
        else {
            (void)strcpy_s(new_buffer, new_buffer_len, PROVIDER_NAME);
        }
    }
    else {
        new_buffer = _strdup(originalValue);
        if (!new_buffer) {
            (void)fprintf(stderr, "%s: Out of memory\n", av[0]);
            res = 1;
            goto out;
        }
    }

    if (uninstall_regkey) {
        char *s;

        DPRINTF(1, ("# value before removal '%s'\n", new_buffer));
        while ((s = strstr(new_buffer, PROVIDER_NAME_COMMA)) != NULL) {
            char *end = s+strlen(PROVIDER_NAME_COMMA);
            (void)memmove(s, end, strlen(end)+1);
            DPRINTF(1, ("# value after removal '%s'\n", new_buffer));
        }

        if (!strcmp(new_buffer, PROVIDER_NAME)) {
            new_buffer[0] = '\0';
        }
    }

    DPRINTF(1, ("# writing '%s'\n", new_buffer));

    /*
     * Set the new value of the ProviderOrder key
     */
    result = RegSetValueExA(hKey, "ProviderOrder", 0, REG_SZ,
        (BYTE *)new_buffer, (DWORD)strlen(new_buffer));

    if (result != ERROR_SUCCESS) {
        (void)fprintf(stderr, "%s: Error setting registry value: %d\n",
            av[0], result);
        res = 1;
    }
    else {
        res = 0;
    }

out:
    free(new_buffer);
    free(originalValue);
    (void)RegCloseKey(hKey);

    return res;
}
