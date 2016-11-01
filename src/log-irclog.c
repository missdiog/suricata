/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * Implements irc logging portion of the engine.
 */

#include "suricata-common.h"
#include "output.h"
#include "log-irclog.h"

#include "app-layer-parser.h"
#include "app-layer-irc.h"

#include "util-logopenfile.h"
#include "util-print.h"

#define DEFAULT_LOG_FILENAME "irc.log"
#define MODULE_NAME "LogIrcLog"
#define OUTPUT_BUFFER_SIZE 65535

typedef struct LogIrcFileCtx_ {
    LogFileCtx *file_ctx;
} LogIrcFileCtx;

typedef struct LogIrcLogThread_ {
    LogIrcFileCtx *irclog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t cmds_cnt;
    MemBuffer *buffer;
} LogIrcLogThread;

/**
 * \brief Logs irc transactions info to logger.
 * \internal
 * \param tv - Pointer to ThreadVars - Not used.
 * \param data - Pointer to ThreadData. Cast to LogIrcLogThread *.
 * \param p - Packet that triggered logging action. Only TCP.
 * \param flow - Flow that triggered logging action.
 * \param state - Pointer to IRC State. Cast to IRCState *.
 * \param tx - Pointer to IRC Transaction. Cast to IRCTransaction *.
 * \param tx_id - The transaction id to log.
 * \retval TM_ECODE_OK (0). Always.
 */
int LogIrcLogger(ThreadVars *tv, void *data, const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCEnter();

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    LogIrcLogThread *aft = (LogIrcLogThread *)data;
    LogIrcFileCtx *irclog = aft->irclog_ctx;
    IRCTransaction *irctx = (IRCTransaction *) tx;
    IRCState *ircstate = (IRCState *) state;

    int ipproto = PKT_IS_IPV4(p) ? AF_INET: AF_INET6;
    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }

    char timebuf[64] = {0};
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

#ifdef DEBUG
    SCLogDebug(
            " ==== WRITE ==== "
            "TS: %s [**] " /* timestamp */
            "FLOW: %s:%" PRIu16 " -> %s:%" PRIu16 " [**] " /* flow */
            "SRV: %s [**] " /* server name */
            "CMD: %s [**] " /* cmd */
            "CMD LINE: %s [**] " /* client cmd line */
            "RSP LINE: %s [**] " /* server cmd line */
            "ALL REQ: %s [**] " /* request */
            "ALL RSP: %s [**] " /* response */
            "BAD_CMD: %d"       /* bad command ? */
            " ==== WRITE ==== "
            "\n",
            timebuf,
            srcip, sp, dstip, dp,
            ircstate->srv.hostname,
            irctx->request_cmd,
            irctx->request_cmd_line,
            irctx->response_cmd_line,
            irctx->request, irctx->response,
            irctx->bad_cmd
                );
#endif

    /* reset */
    MemBufferReset(aft->buffer);

    MemBufferWriteString( aft->buffer,
            "%s [**] " /* timestamp */
            "%s:%" PRIu16 " -> %s:%" PRIu16 " [**] " /* flow */
            "%s [**] " /* server name */
            "%s [**] " /* cmd */
            "%s [**] " /* client cmd line */
            "%s [**] " /* server cmd line */
#ifdef DEBUG
            "%s [**] " /* request */
            "%s [**] " /* response */
#endif
            "%d"       /* bad command ? */
            "\n",
            timebuf,
            srcip, sp, dstip, dp,
            ircstate->srv.hostname,
            irctx->request_cmd,
            irctx->request_cmd_line,
            irctx->response_cmd_line,
#ifdef DEBUG
            irctx->request, irctx->response,
#endif
            irctx->bad_cmd
                );

    SCMutexLock(&irclog->file_ctx->fp_mutex);
    ++aft->cmds_cnt;
    irclog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
            MEMBUFFER_OFFSET(aft->buffer), irclog->file_ctx);
    SCMutexUnlock(&irclog->file_ctx->fp_mutex);

end:
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Allocates and initializes Log IRC Thread data.
 * \internal
 * \param t - ThreadVars - Not used.
 * \param inidata - Output context. Cast to OutputCtx *.
 * \param data - Return param with allocated LogIRCLogThread data .
 * \retval TM_ECODE_FAILED  (1) - if allocation or initialization failed.
 * \retval TM_ECODE_OK (0) - If successful.
 */
TmEcode LogIrcLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogIrcLogThread *aft = SCMalloc(sizeof(LogIrcLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogIrcLogThread));

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for LogHTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->irclog_ctx= ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

/**
 * \brief Frees Log IRC Thread data.
 * \internal
 * \param t - ThreadVars - Not used.
 * \param data - Log IRC Thread data. Cast to LogIRCLogThread *.
 * \retval TM_ECODE_OK (0) - Always.
 */
TmEcode LogIrcLogThreadDeinit(ThreadVars *t, void *data)
{
    LogIrcLogThread *aft = (LogIrcLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogIrcLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

/**
 * \brief Frees logger and output context for IRC.
 * \param output_ctx - The output context.
 */
static void LogIrcLogDeInitCtx(OutputCtx *output_ctx)
{
    LogIrcFileCtx *irclog_ctx = (LogIrcFileCtx *)output_ctx->data;

    LogFileFreeCtx(irclog_ctx->file_ctx);

    SCFree(irclog_ctx);
    SCFree(output_ctx);
}


/** \brief Create a new irc log LogFileCtx.
 *  \param conf - Pointer to ConfNode containing this loggers configuration.
 *  \retval NULL if failure
 *  \retval LogFileCtx* to the file_ctx if succesful.
 * */
OutputCtx *LogIrcLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogIrcFileCtx *irclog_ctx = SCMalloc(sizeof(LogIrcFileCtx));
    if (unlikely(irclog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(irclog_ctx, 0x00, sizeof(LogIrcFileCtx));
    irclog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        /*FIXME - mem leak */
        return NULL;
    }

    output_ctx->data = irclog_ctx;
    output_ctx->DeInit = LogIrcLogDeInitCtx;
    SCLogDebug("IRC log output initialized");

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_IRC);

    return output_ctx;
}

/**
 * \brief The IRC log stats on exit.
 * \internal
 * \param tv - The ThreadVars pointer.  Not used.
 * \param data - Thre Log IRC Thread data. Cast to LogIrcLogThread *.
 */
void LogIrcLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogIrcLogThread *aft = (LogIrcLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("IRC logger logged %" PRIu32 " commands or responses", aft->cmds_cnt);
}

/**
 * \brief Register the IRC protocol logger.
 */
void LogIrcLogRegister(void)
{
    OutputRegisterTxModule(LOGGER_IRC, MODULE_NAME, "irc-log",
            LogIrcLogInitCtx, ALPROTO_IRC, LogIrcLogger, LogIrcLogThreadInit,
            LogIrcLogThreadDeinit, LogIrcLogExitPrintStats);
}

