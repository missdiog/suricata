/* vi: set et ts=4: */
/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Mike Pomraning <mpomraning@qualys.com>
 *
 * File-like output for logging:  regular files and sockets.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "tm-modules.h"      /* LogFileCtx */
#include "conf.h"            /* ConfNode, etc. */
#include "output.h"          /* DEFAULT_LOG_* */
#include "util-logopenfile.h"
#include "util-logopenfile-tile.h"

#ifdef HAVE_LIBHIREDIS
#include "util-logopenfile-redis.h"
#endif /* HAVE_LIBHIREDIS */

/** \brief connect to the indicated local stream socket, logging any errors
 *  \param path filesystem path to connect to
 *  \param log_err, non-zero if connect failure should be logged.
 *  \retval FILE* on success (fdopen'd wrapper of underlying socket)
 *  \retval NULL on error
 */
static FILE *
SCLogOpenUnixSocketFp(const char *path, int sock_type, int log_err)
{
    struct sockaddr_un saun;
    int s = -1;
    FILE * ret = NULL;

    memset(&saun, 0x00, sizeof(saun));

    s = socket(PF_UNIX, sock_type, 0);
    if (s < 0) goto err;

    saun.sun_family = AF_UNIX;
    strlcpy(saun.sun_path, path, sizeof(saun.sun_path));

    if (connect(s, (const struct sockaddr *)&saun, sizeof(saun)) < 0)
        goto err;

    ret = fdopen(s, "w");
    if (ret == NULL)
        goto err;

    return ret;

err:
    if (log_err)
        SCLogWarning(SC_ERR_SOCKET,
            "Error connecting to socket \"%s\": %s (will keep trying)",
            path, strerror(errno));

    if (s >= 0)
        close(s);

    return NULL;
}

/**
 * \brief Attempt to reconnect a disconnected (or never-connected) Unix domain socket.
 * \retval 1 if it is now connected; otherwise 0
 */
static int SCLogUnixSocketReconnect(LogFileCtx *log_ctx)
{
    int disconnected = 0;
    if (log_ctx->fp) {
        SCLogWarning(SC_ERR_SOCKET,
            "Write error on Unix socket \"%s\": %s; reconnecting...",
            log_ctx->filename, strerror(errno));
        fclose(log_ctx->fp);
        log_ctx->fp = NULL;
        log_ctx->reconn_timer = 0;
        disconnected = 1;
    }

    struct timeval tv;
    uint64_t now;
    gettimeofday(&tv, NULL);
    now = (uint64_t)tv.tv_sec * 1000;
    now += tv.tv_usec / 1000;           /* msec resolution */
    if (log_ctx->reconn_timer != 0 &&
            (now - log_ctx->reconn_timer) < LOGFILE_RECONN_MIN_TIME) {
        /* Don't bother to try reconnecting too often. */
        return 0;
    }
    log_ctx->reconn_timer = now;

    log_ctx->fp = SCLogOpenUnixSocketFp(log_ctx->filename, log_ctx->sock_type, 0);
    if (log_ctx->fp) {
        /* Connected at last (or reconnected) */
        SCLogNotice("Reconnected socket \"%s\"", log_ctx->filename);
    } else if (disconnected) {
        SCLogWarning(SC_ERR_SOCKET, "Reconnect failed: %s (will keep trying)",
            strerror(errno));
    }

    return log_ctx->fp ? 1 : 0;
}

/**
 * \brief Write buffer to log file.
 * \retval 0 on failure; otherwise, the return value of fwrite (number of
 * characters successfully written).
 */
static int SCLogFileWrite(const char *buffer, int buffer_len, LogFileCtx *log_ctx)
{
    /* Check for rotation. */
    if (log_ctx->rotation_flag) {
        log_ctx->rotation_flag = 0;
        SCConfLogReopen(log_ctx);
    }

    int ret = 0;

    if (log_ctx->fp == NULL && log_ctx->is_sock)
        SCLogUnixSocketReconnect(log_ctx);

    if (log_ctx->fp) {
        clearerr(log_ctx->fp);
        ret = fwrite(buffer, buffer_len, 1, log_ctx->fp);
        fflush(log_ctx->fp);

        if (ferror(log_ctx->fp) && log_ctx->is_sock) {
            /* Error on Unix socket, maybe needs reconnect */
            if (SCLogUnixSocketReconnect(log_ctx)) {
                ret = fwrite(buffer, buffer_len, 1, log_ctx->fp);
                fflush(log_ctx->fp);
            }
        }
    }

    return ret;
}

static void SCLogFileClose(LogFileCtx *log_ctx)
{
    if (log_ctx->fp)
        fclose(log_ctx->fp);
}

/** \brief open the indicated file, logging any errors
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \retval FILE* on success
 *  \retval NULL on error
 */
static FILE *
SCLogOpenFileFp(const char *path, const char *append_setting)
{
    FILE *ret = NULL;

    if (ConfValIsTrue(append_setting)) {
        ret = fopen(path, "a");
    } else {
        ret = fopen(path, "w");
    }

    if (ret == NULL)
        SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s",
                   path, strerror(errno));
    return ret;
}

/** \brief open the indicated file remotely over PCIe to a host
 *  \param path filesystem path to open
 *  \param append_setting open file with O_APPEND: "yes" or "no"
 *  \retval FILE* on success
 *  \retval NULL on error
 */
static PcieFile *SCLogOpenPcieFp(LogFileCtx *log_ctx, const char *path, 
                                 const char *append_setting)
{
#ifndef __tile__
    SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
               "PCIe logging only supported on Tile-Gx Architecture.");
    return NULL;
#else
    return TileOpenPcieFp(log_ctx, path, append_setting);
#endif
}

/** \brief open a generic output "log file", which may be a regular file or a socket
 *  \param conf ConfNode structure for the output section in question
 *  \param log_ctx Log file context allocated by caller
 *  \param default_filename Default name of file to open, if not specified in ConfNode
 *  \param rotate Register the file for rotation in HUP.
 *  \retval 0 on success
 *  \retval -1 on error
 */
int
SCConfLogOpenGeneric(ConfNode *conf,
                     LogFileCtx *log_ctx,
                     const char *default_filename,
                     int rotate)
{
    char log_path[PATH_MAX];
    char *log_dir;
    const char *filename, *filetype;

    // Arg check
    if (conf == NULL || log_ctx == NULL || default_filename == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric(conf %p, ctx %p, default %p) "
                   "missing an argument",
                   conf, log_ctx, default_filename);
        return -1;
    }
    if (log_ctx->fp != NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,
                   "SCConfLogOpenGeneric: previously initialized Log CTX "
                   "encountered");
        return -1;
    }

    // Resolve the given config
    filename = ConfNodeLookupChildValue(conf, "filename");
    if (filename == NULL)
        filename = default_filename;

    log_dir = ConfigGetLogDirectory();

    if (PathIsAbsolute(filename)) {
        snprintf(log_path, PATH_MAX, "%s", filename);
    } else {
        snprintf(log_path, PATH_MAX, "%s/%s", log_dir, filename);
    }

    filetype = ConfNodeLookupChildValue(conf, "filetype");
    if (filetype == NULL)
        filetype = DEFAULT_LOG_FILETYPE;

    const char *append = ConfNodeLookupChildValue(conf, "append");
    if (append == NULL)
        append = DEFAULT_LOG_MODE_APPEND;

    // Now, what have we been asked to open?
    if (strcasecmp(filetype, "unix_stream") == 0) {
        /* Don't bail. May be able to connect later. */
        log_ctx->is_sock = 1;
        log_ctx->sock_type = SOCK_STREAM;
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_STREAM, 1);
    } else if (strcasecmp(filetype, "unix_dgram") == 0) {
        /* Don't bail. May be able to connect later. */
        log_ctx->is_sock = 1;
        log_ctx->sock_type = SOCK_DGRAM;
        log_ctx->fp = SCLogOpenUnixSocketFp(log_path, SOCK_DGRAM, 1);
    } else if (strcasecmp(filetype, DEFAULT_LOG_FILETYPE) == 0 ||
               strcasecmp(filetype, "file") == 0) {
        log_ctx->fp = SCLogOpenFileFp(log_path, append);
        if (log_ctx->fp == NULL)
            return -1; // Error already logged by Open...Fp routine
        log_ctx->is_regular = 1;
        if (rotate) {
            OutputRegisterFileRotationFlag(&log_ctx->rotation_flag);
        }
    } else if (strcasecmp(filetype, "pcie") == 0) {
        log_ctx->pcie_fp = SCLogOpenPcieFp(log_ctx, log_path, append);
        if (log_ctx->pcie_fp == NULL)
            return -1; // Error already logged by Open...Fp routine
#ifdef HAVE_LIBHIREDIS
    } else if (strcasecmp(filetype, "redis") == 0) {
        ConfNode *redis_node = ConfNodeLookupChild(conf, "redis");
        if (SCConfLogOpenRedis(redis_node, log_ctx) < 0) {
            SCLogError(SC_ERR_REDIS, "failed to open redis output");
            return -1;
        }
        log_ctx->type = LOGFILE_TYPE_REDIS;
#endif
    } else {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry for "
                   "%s.filetype.  Expected \"regular\" (default), \"unix_stream\", "
                   "\"pcie\" "
                   "or \"unix_dgram\"",
                   conf->name);
    }
    log_ctx->filename = SCStrdup(log_path);
    if (unlikely(log_ctx->filename == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Failed to allocate memory for filename");
        return -1;
    }

    SCLogInfo("%s output device (%s) initialized: %s", conf->name, filetype,
              filename);

    return 0;
}

/**
 * \brief Reopen a regular log file with the side-affect of truncating it.
 *
 * This is useful to clear the log file and start a new one, or to
 * re-open the file after its been moved by something external
 * (eg. logrotate).
 */
int SCConfLogReopen(LogFileCtx *log_ctx)
{
    if (!log_ctx->is_regular) {
        /* Not supported and not needed on non-regular files. */
        return 0;
    }

    if (log_ctx->filename == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT,
            "Can't re-open LogFileCtx without a filename.");
        return -1;
    }

    fclose(log_ctx->fp);

    /* Reopen the file. Append is forced in case the file was not
     * moved as part of a rotation process. */
    SCLogDebug("Reopening log file %s.", log_ctx->filename);
    log_ctx->fp = SCLogOpenFileFp(log_ctx->filename, "yes");
    if (log_ctx->fp == NULL) {
        return -1; // Already logged by Open..Fp routine.
    }

    return 0;
}

/** \brief LogFileNewCtx() Get a new LogFileCtx
 *  \retval LogFileCtx * pointer if succesful, NULL if error
 *  */
LogFileCtx *LogFileNewCtx(void)
{
    LogFileCtx* lf_ctx;
    lf_ctx = (LogFileCtx*)SCMalloc(sizeof(LogFileCtx));

    if (lf_ctx == NULL)
        return NULL;
    memset(lf_ctx, 0, sizeof(LogFileCtx));

    SCMutexInit(&lf_ctx->fp_mutex,NULL);

    // Default Write and Close functions
    lf_ctx->Write = SCLogFileWrite;
    lf_ctx->Close = SCLogFileClose;

#ifdef HAVE_LIBHIREDIS
    lf_ctx->redis_setup.batch_count = 0;
#endif /* HAVE_LIBHIREDIS */

    return lf_ctx;
}

/** \brief LogFileFreeCtx() Destroy a LogFileCtx (Close the file and free memory)
 *  \param motcx pointer to the OutputCtx
 *  \retval int 1 if succesful, 0 if error
 *  */
int LogFileFreeCtx(LogFileCtx *lf_ctx)
{
    if (lf_ctx == NULL) {
        SCReturnInt(0);
    }

    if (lf_ctx->fp != NULL) {
        SCMutexLock(&lf_ctx->fp_mutex);
        lf_ctx->Close(lf_ctx);
        SCMutexUnlock(&lf_ctx->fp_mutex);
    }

#ifdef HAVE_LIBHIREDIS
    if (lf_ctx->type == LOGFILE_TYPE_REDIS) {
        if (lf_ctx->redis_setup.server)
            SCFree(lf_ctx->redis_setup.server);
        if (lf_ctx->redis_setup.key)
            SCFree(lf_ctx->redis_setup.key);
        if (lf_ctx->redis) {
            SCLogRedisContextFree(lf_ctx->redis, lf_ctx->redis_setup.async);
        }
    }
#endif

    SCMutexDestroy(&lf_ctx->fp_mutex);

    if (lf_ctx->prefix != NULL) {
        SCFree(lf_ctx->prefix);
        lf_ctx->prefix_len = 0;
    }

    if(lf_ctx->filename != NULL)
        SCFree(lf_ctx->filename);

    if (lf_ctx->sensor_name)
        SCFree(lf_ctx->sensor_name);

    OutputUnregisterFileRotationFlag(&lf_ctx->rotation_flag);

    SCFree(lf_ctx);

    SCReturnInt(1);
}

int LogFileWrite(LogFileCtx *file_ctx, MemBuffer *buffer)
{
    if (file_ctx->type == LOGFILE_TYPE_SYSLOG) {
        syslog(file_ctx->syslog_setup.alert_syslog_level, "%s",
                (const char *)MEMBUFFER_BUFFER(buffer));
    } else if (file_ctx->type == LOGFILE_TYPE_FILE ||
               file_ctx->type == LOGFILE_TYPE_UNIX_DGRAM ||
               file_ctx->type == LOGFILE_TYPE_UNIX_STREAM)
    {
        /* append \n for files only */
        MemBufferWriteString(buffer, "\n");
        SCMutexLock(&file_ctx->fp_mutex);
        file_ctx->Write((const char *)MEMBUFFER_BUFFER(buffer),
                        MEMBUFFER_OFFSET(buffer), file_ctx);
        SCMutexUnlock(&file_ctx->fp_mutex);
    }
#ifdef HAVE_LIBHIREDIS
    else if (file_ctx->type == LOGFILE_TYPE_REDIS) {
        SCMutexLock(&file_ctx->fp_mutex);
        LogFileWriteRedis(file_ctx, (const char *)MEMBUFFER_BUFFER(buffer),
                MEMBUFFER_OFFSET(buffer));
        SCMutexUnlock(&file_ctx->fp_mutex);
    }
#endif

    return 0;
}
