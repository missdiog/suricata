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
 * App-layer parser for IRC protocol
 *
 */
#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-irc.h"
#include "util-print.h"
#include "util-memcmp.h"
#include <ctype.h>

/* -------------- COMMANDS ------------------- */
#define IRC_CMD_ADMIN     "ADMIN"
#define IRC_CMD_AWAY      "AWAY"
#define IRC_CMD_CNOTICE   "CNOTICE"
#define IRC_CMD_CPRIVMSG  "CPRIVMSG"
#define IRC_CMD_CONNECT   "CONNECT"
#define IRC_CMD_DIE       "DIE"
#define IRC_CMD_ENCAP     "ENCAP"
#define IRC_CMD_ERROR     "ERROR"
#define IRC_CMD_HELP      "HELP"
#define IRC_CMD_INFO      "INFO"
#define IRC_CMD_INVITE    "INVITE"
#define IRC_CMD_ISON      "ISON"
#define IRC_CMD_JSON      "JOIN"
#define IRC_CMD_KICK      "KICK"
#define IRC_CMD_KILL      "KILL"
#define IRC_CMD_KNOCK     "KNOCK"
#define IRC_CMD_LINKS     "LINKS"
#define IRC_CMD_LIST      "LIST"
#define IRC_CMD_LUSERS    "LUSERS"
#define IRC_CMD_MODE      "MODE"
#define IRC_CMD_MOTD      "MOTD"
#define IRC_CMD_NAME      "NAMES"
#define IRC_CMD_NAMESX    "NAMESX"
#define IRC_CMD_NICK      "NICK"
#define IRC_CMD_NOTICE    "NOTICE"
#define IRC_CMD_OPER      "OPER"
#define IRC_CMD_PART      "PART"
#define IRC_CMD_PASS      "PASS"
#define IRC_CMD_PING      "PING"
#define IRC_CMD_PONG      "PONG"
#define IRC_CMD_PRIVMSG   "PRIVMSG"
#define IRC_CMD_QUIT      "QUIT"
#define IRC_CMD_REHASH    "REHASH"
#define IRC_CMD_RESTART   "RESTART"
#define IRC_CMD_RULES     "RULES"
#define IRC_CMD_SERVER    "SERVER"
#define IRC_CMD_SERVICE   "SERVICE"
#define IRC_CMD_SERVLIST  "SERVLIST"
#define IRC_CMD_SQUERY    "SQUERY"
#define IRC_CMD_SQUIT     "SQUIT"
#define IRC_CMD_SETNAME   "SETNAME"
#define IRC_CMD_SILENCE   "SILENCE"
#define IRC_CMD_STATS     "STATS"
#define IRC_CMD_SUMMON    "SUMMON"
#define IRC_CMD_TIME      "TIME"
#define IRC_CMD_TOPIC     "TOPIC"
#define IRC_CMD_TRACE     "TRACE"
#define IRC_CMD_UHNAMES   "UHNAMES"
#define IRC_CMD_USER      "USER"
#define IRC_CMD_USERHOST  "USERHOST"
#define IRC_CMD_USERIP    "USERIP"
#define IRC_CMD_USERS     "USERS"
#define IRC_CMD_VERSION   "VERSION"
#define IRC_CMD_WALLOPS   "WALLOPS"
#define IRC_CMD_WATCH     "WATCH"
#define IRC_CMD_WHO       "WHO"
#define IRC_CMD_WHOIS     "WHOIS"
#define IRC_CMD_WHOWAS    "WHOWAS"

typedef struct IRCCommandName_ {
    const char *name;
    size_t size;
} IRCCommandName;

#define IRC_COMMAND_STRUCT(NAME)      { NAME, strlen(NAME) }
/* The list of IRC commands that we know */
const IRCCommandName irc_commands[] = {
    IRC_COMMAND_STRUCT(IRC_CMD_ADMIN)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_AWAY)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_CNOTICE)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_CPRIVMSG)  ,
    IRC_COMMAND_STRUCT(IRC_CMD_CONNECT)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_DIE)       ,
    IRC_COMMAND_STRUCT(IRC_CMD_ENCAP)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_ERROR)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_HELP)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_INFO)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_INVITE)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_ISON)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_JSON)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_KICK)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_KILL)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_KNOCK)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_LINKS)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_LIST)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_LUSERS)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_MODE)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_MOTD)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_NAME)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_NAMESX)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_NICK)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_NOTICE)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_OPER)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_PART)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_PASS)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_PING)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_PONG)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_PRIVMSG)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_QUIT)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_REHASH)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_RESTART)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_RULES)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_SERVER)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_SERVICE)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_SERVLIST)  ,
    IRC_COMMAND_STRUCT(IRC_CMD_SQUERY)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_SQUIT)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_SETNAME)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_SILENCE)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_STATS)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_SUMMON)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_TIME)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_TOPIC)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_TRACE)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_UHNAMES)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_USER)      ,
    IRC_COMMAND_STRUCT(IRC_CMD_USERHOST)  ,
    IRC_COMMAND_STRUCT(IRC_CMD_USERIP)    ,
    IRC_COMMAND_STRUCT(IRC_CMD_USERS)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_VERSION)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_WALLOPS)   ,
    IRC_COMMAND_STRUCT(IRC_CMD_WATCH)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_WHO)       ,
    IRC_COMMAND_STRUCT(IRC_CMD_WHOIS)     ,
    IRC_COMMAND_STRUCT(IRC_CMD_WHOWAS)
};

/* \brief The number of existing irc commands */
static size_t num_irc_commands = 0;

/**
 *  \brief  Allocs a IRC transaction.
 *  \internal
 *  \param state - IRC app layer state.
 *  \param tx_id - The transction id.
 *  \TODO memcap
 *  \retval IRCTransaction * - The allocated transaction.
 *  \retval NULL - If allocation fails
 */
static IRCTransaction *IRCTransactionAlloc(IRCState *state, const uint16_t tx_id)
{
    IRCTransaction *tx = SCMalloc(sizeof(IRCTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    memset(tx, 0x00, sizeof(IRCTransaction));
    tx->tx_num = tx_id;
    tx->request = NULL;
    tx->request_len = 0;

    tx->response = NULL;
    tx->response_len = 0;

    tx->logged = 0;
    tx->bad_cmd = 0;

    return tx;
}

/**
 *  \brief Free a IRC Transaction.
 *  \internal
 *  \param tx - IRC Transaction to free
 *  \param state - IRC app layer state.
 *  \TODO memcap
 */
static void IRCTransactionFree(IRCTransaction *tx, IRCState *state)
{
    SCEnter();
    if (tx->request != NULL)
        SCFree(tx->request);
    if (tx->response != NULL)
        SCFree(tx->response);
    if (tx->request_cmd != NULL)
        SCFree(tx->request_cmd);
    if (tx->request_cmd_line != NULL)
        SCFree(tx->request_cmd_line);
    if (tx->response_cmd_line != NULL)
        SCFree(tx->response_cmd_line);

    if (tx != NULL)
        SCFree(tx);

    SCReturn;
}


/**
 * \brief Helper function trim trailing spaces from command argument.
 * \internal
 * \param input - input buffer.
 * \param input_len - input buffer length.
 */
static void IRCParseCommandArgTrim(uint8_t *input, uint32_t input_len)
{
    if (input_len == 0)
        return;
    if (input == NULL)
        return;

    for (uint32_t i = input_len; i > 0 ; --i) {
        if (isspace(*(input+i))) {
            *(input+i) = '\0';
            continue;
        }
    }
}

/**
 * \brief Function to calculate command length.
 * \internal
 * \param input - input buffer.
 * \param input_len - input buffer length.
 * \retval uint32_t - the command length.
 */
static uint32_t IRCParseCommandEndOffset(uint8_t *input, uint32_t input_len)
{
    if (input_len == 0)
        return 0;
    if(input == NULL)
        return 0;

    uint8_t *ptr = input;
    for(uint32_t i = 0; i < input_len; ++i) {
        if (isspace(*ptr)) {
            return i;
        }
        ++ptr;
    }
    return 0;
}
/**
 * \brief Function to copy input to a new string.
 * \internal
 * \param input - input buffer.
 * \param input_len - input buffer length.
 * \retval char * - The location for the buffer copy.
 * \retval NULL - If nothing to copy
 */
static char * IRCCopyInput(uint8_t *input, uint32_t input_len)
{
    if (! input)
        return NULL;
    if (! input_len)
        return NULL;
    char * ret = SCMalloc(input_len + 1);
    if (!ret)
        return NULL;
    memset(ret, 0, input_len+1);
    memcpy(ret, input, input_len);

    return ret;
}

/** \brief Function to parse IRC client command and alloc buffer.
 *  \internal
 *
 *  \param input - input buffer.
 *  \param input_len - the input length;
 *  \param cmd_len - ouput parameter with command length.
 *  \retval char * - the command copy buffer.
 *  \retval NULL   - if allocation fails.
 */
static char * IRCParseCommandAlloc(uint8_t *input, uint32_t input_len, uint32_t* cmd_len)
{
    char * cmd = NULL;
    uint32_t command_size = IRCParseCommandEndOffset(input, input_len);

    *cmd_len = command_size;
    if (! command_size) {
        return cmd;
    }
    cmd = SCMalloc(command_size + 1);
    if (unlikely(cmd == NULL)) {
        return NULL;
    }
    memset(cmd, 0, command_size + 1);
    memcpy(cmd, input, command_size);

    return cmd;
}

/**
 *  \brief Creates a copy of input IRC request.
 *  \internal
 *  \param input - Input buffer.
 *  \retval char * - The copy of request.
 *  \retval NULL   - If allocation of parsing fails.
 */
static char * IRCParseRequestCopyLine(uint8_t *input)
{

    if (! input) {
        return NULL;
    }

    char  *end = strchr((char *)input, '\r');
    if (end == NULL)
        end = strchr((char *)input, '\n');
    if (end != NULL) {
        uint32_t len = end-(char *)input;
        return IRCCopyInput((uint8_t *)input, len);
    }

    return NULL;
}

/**
 *  \brief Creates a copy of input IRC response.
 *  \internal
 *  \param input - Input buffer.
 *  \retval char * - The copy of response.
 *  \retval NULL   - If allocation of parsing fails.
 */
static char * IRCParseResponseCopyLine(uint8_t *input)
{
    if (! input) {
        return NULL;
    }

    char * sep =  strchr((char *)input, ' ');
    if (sep != NULL) {
        sep++;
        char  *end = strchr(sep, '\r');
        if (end == NULL)
            end = strchr(sep, '\n');
        if (end != NULL) {
            uint32_t len = end-sep;
            return IRCCopyInput((uint8_t *)sep, len);
        }
    }

    return NULL;
}

/** \brief Function to parse IRC client command request.
 *  \internal
 *  \param f - Session flow.
 *  \param state - IRC state. Should be casted to IRCState.
 *  \param pstate - App layer parser state.
 *  \param input - The input data seen from protocol parser.
 *  \param input_len - The input data length seen from protocol parser.
 *  \param local_data - Opaque data. Not used.
 *  \retval 0 - If we want to consider this request.
 *  \retval -1 - If we dont' want to consider this request.
 */
static int IRCParseRequest(Flow *f, void *state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len,
        void *local_data)
{

    SCEnter();

    IRCState *irc_state = (IRCState *)state;
    if (irc_state == NULL) {
        SCReturnInt(-1);
    }

    IRCTransaction *tx = NULL;
    if (input != NULL && input_len != 0) {
        tx = IRCTransactionAlloc(irc_state, irc_state->transaction_max);
        if (tx == NULL) {
            SCReturnInt(-1);
        }
    }
    irc_state->transaction_max++;

    //TODO: dns_state->curr = tx;
#ifdef DEBUG
    SCLogDebug("IRC = new tx with internal num %u", tx->tx_num);
#endif
    //TODO: dns_state->unreplied_cnt++;

    uint32_t command_size = 0;
    char * cmd = IRCParseCommandAlloc(input, input_len, &command_size);

    if (command_size == 4) {
        int is_nick = 0;
        int is_user = 0;

        if (SCMemcmp(input, IRC_CMD_NICK, 4) == 0)
            is_nick = 1;
        if (SCMemcmp(input, IRC_CMD_USER, 4) == 0)
            is_user = 1;

        /* Save nick or user arguments */
        if (input_len >= 6 && (is_nick || is_user)) {
            size_t cmd_arg_sz = input_len - 1 - command_size;
            uint8_t *save = is_nick ? irc_state->cli.nick : irc_state->cli.user;
            save = SCMalloc(cmd_arg_sz);
            if (save != NULL) {
                memset(save, 0, cmd_arg_sz);
                memcpy(save, input+command_size+1, cmd_arg_sz);
                IRCParseCommandArgTrim(save, cmd_arg_sz);
            }
            goto end;
        }
    }

    /* QUIT COMMAND */
    if (command_size == 4 && SCMemcmp(input, IRC_CMD_QUIT, 4) == 0 ) {
        irc_state->cli.quitted = 1;
        goto end;
    }
    /* PASS command - Uncommon */
    if (command_size == 4 &&  SCMemcmp(input, IRC_CMD_PASS, 4) == 0 ) {
        irc_state->cli.authenticated = 1;
        goto end;
    }

    int cmd_not_found = 1;
    /* Check for unknown command and */
    for (size_t i = 0 ; i < num_irc_commands -1 ; ++i) {
        if (command_size == irc_commands[i].size &&
                SCMemcmp(input, irc_commands[i].name, command_size) == 0 ) {
            cmd_not_found = 0;
            break;
        }
    }
    if (cmd_not_found) {
        irc_state->cli.num_bad_cmds++;
        if (tx) {
            tx->bad_cmd = 1;
        }
    }

end:
    /* Insert transaction in queue*/
    if (tx != NULL) {
        tx->request_cmd = cmd;
        tx->request_cmd_line = IRCParseRequestCopyLine(input);
        tx->request_len = input_len;
        tx->request = IRCCopyInput(input, input_len);
#ifdef DEBUG
        SCLogDebug("IRC REQUEST TXLIST:[%p] CMD:[%s] INPUT:[%s] LEN:[%d] BAD_CMD=[%d]",
                &irc_state->tx_list, tx->request_cmd, tx->request, tx->request_len,
                tx->bad_cmd);
#endif
        irc_state->curr_tx = tx;
        TAILQ_INSERT_TAIL(&irc_state->tx_list, tx, next);
    }
    SCReturnInt(1);
}


/** \brief Function to parse IRC server responses and commands.
 *  \internal
 *  \param f - Session flow.
 *  \param state - IRC state. Should be casted to IRCState.
 *  \param pstate - App layer parser state.
 *  \param input - The input data seen from protocol parser.
 *  \param input_len - The input data length seen from protocol parser.
 *  \param local_data - Opaque data. Not used.
 *  \retval 0 - If we want to consider this response.
 *  \retval -1 - If we dont' want to consider this response.
 */
static int IRCParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len,
        void *local_data)
{
    SCEnter();

    IRCState *irc_state = (IRCState *)state;
    if (irc_state == NULL) {
        SCReturnInt(-1);
    }

    IRCTransaction *tx = TAILQ_LAST(&irc_state->tx_list, _list);
    if (tx) {
        /* Server side starts data - not a response. */
        if (tx->response) {
            SCReturnInt(0);
        }
        /* Update response on last transaction */
        tx->response_len = input_len;
        tx->response = IRCCopyInput(input, input_len);
#ifdef DEBUG
        SCLogDebug("TX=%d, IRC RESPONSE INPUT: %s [%d]", tx->tx_num, tx->response, tx->response_len);
#endif
    }

    if (input && *input == ':') {
        if (irc_state->srv.hostname == NULL) {
            /* Sets irc hostanme */
            uint32_t host_size = IRCParseCommandEndOffset(input+1, input_len-1);
            irc_state->srv.hostname = IRCCopyInput(input+1, host_size);
        }

    }

    if (tx) {
        tx->response_cmd_line = IRCParseResponseCopyLine(input);
    }

    SCReturnInt(1);
}

/**
 *  \brief Sets transaction as logged.
 *  \param alstate - Not used.
 *  \param tx - pointer to transaction. Cast to IRCTransaction *.
 *  \param logger - reports if tx was logged.
 *  \internal
 */
void IRCSetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    IRCTransaction *irc_tx = (IRCTransaction *)tx;
    irc_tx->logged |= logger;
#ifdef DEBUG
    SCLogDebug("SetTxLogger: id:[%d] cli:[%s] srv:[%s] val:[%d]",
            irc_tx->tx_num, irc_tx->request_cmd_line, irc_tx->response_cmd_line, logger);
#endif
}

/**
 *  \brief Checks if transaction was logged.
 *  \internal
 *  \param alstate - Not used.
 *  \param tx - pointer to transaction. Cast to IRCTransaction *.
 *  \param logger - to check if tx has logged
 *  \retval 1 - if already logged
 *  \retval 0 - if not yet logged
 */
int IRCGetTxLogged(void *alstate, void *tx, uint32_t logger)
{
    IRCTransaction *irc_tx = (IRCTransaction *)tx;
#ifdef DEBUG
    SCLogDebug("GetTxLogger: id:[%d] cli:[%s] srv:[%s] logged:[%d] val:[%d]",
            irc_tx->tx_num, irc_tx->request_cmd_line, irc_tx->response_cmd_line,
            irc_tx->logged, logger);
#endif
    if (irc_tx->logged & logger) {
        return 1;
    }
    return 0;
}


/**
 *  \brief Gets a transaction by id.
 *         For performance issues, it checks if it is the current transation.
 *  \param alstate - pointer to state. Cast to IRCState *.
 *  \param tx_id - the transaction if
 *  \retval IRCTransaction *tx - if found as void *.
 *  \retval NULL - if not found.
 */
void *IRCGetTx(void *alstate, uint64_t tx_id)
{
    IRCState *irc_state = (IRCState *)alstate;
    IRCTransaction *tx = NULL;

    if (irc_state->curr_tx == NULL)
        return NULL;
    if (irc_state->curr_tx->tx_num == tx_id)
        return irc_state->curr_tx;

    TAILQ_FOREACH(tx, &irc_state->tx_list, next) {
#ifdef DEBUG
        SCLogDebug("tx->tx_num %u, tx_id %"PRIu64, tx->tx_num, (tx_id+1));
#endif
        if ((tx_id+1) != tx->tx_num)
            continue;
#ifdef DEBUG
        SCLogDebug("returning tx %p", tx);
        //TODO: dns_state->iter = tx;
#endif
        return tx;
    }

    return NULL;
}

/**
 *  \brief Gets the IRC transactions count.
 *  \internal
 *  \param alstate - pointer to state. Cast to IRCState *.
 *  \retval uint64_t - the number of seen transactions.
 */
uint64_t IRCGetTxCnt(void *alstate)
{
    IRCState *irc_state = (IRCState *)alstate;
    return (uint64_t)irc_state->transaction_max;
}

/**
 *  \brief Frees IRC transaction from IRC State.
 *  \internal
 *  \param state - pointer to state. Cast to IRCState *.
 *  \param tx_id - the transaction to cleanup.
 */
static void IRCStateTransactionFree (void *state, uint64_t tx_id)
{
    IRCState *irc_state = state;

    if (irc_state == NULL) {
        return;
    }

    IRCTransaction *tx = NULL;
    TAILQ_FOREACH(tx, &irc_state->tx_list, next) {
        if (tx_id < tx->tx_num)
            break;
        else if (tx_id > tx->tx_num)
            continue;

        if (tx == irc_state->curr_tx)
            irc_state->curr_tx = NULL;

        TAILQ_REMOVE(&irc_state->tx_list, tx, next);
        IRCTransactionFree(tx, state);
        break;
    }
}

/** \brief Function to allocates the IRC state memory.
 *  \internal
 *  \retval IRCState pointer - The allocated IRC state.
 *  \retval NULL - if allocation failed.
 */
static void *IRCStateAlloc(void)
{
    SCEnter();
    void *s = SCMalloc(sizeof(IRCState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(IRCState));

    IRCState *st = s;
    st->cli.nick = NULL;
    st->cli.user = NULL;
    st->cli.authenticated = 0;
    st->cli.quitted = 0;
    st->cli.num_bad_cmds = 0;
    st->srv.hostname = NULL;
    st->transaction_max = 0 ;
    TAILQ_INIT(&st->tx_list);

#ifdef DEBUG
    SCLogDebug("TX LIST=%p", &st->tx_list);
#endif

    return s;
}

/** \brief Function to free the IRC state memory
 *  \param state - pointer to state. Cast to IRCState *.
 *  \internal
*/
static void IRCStateFree(void *state)
{
    SCEnter();
    IRCState *irc_state = (IRCState *)state;
    if (irc_state== NULL)
        return;
    if (irc_state->cli.nick != NULL) {
        SCFree(irc_state->cli.nick);
    }
    if (irc_state->cli.user != NULL) {
        SCFree(irc_state->cli.user);
    }
    if (irc_state->srv.hostname != NULL) {
        SCFree(irc_state->srv.hostname);
    }
    IRCTransaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&irc_state->tx_list))) {
        TAILQ_REMOVE(&irc_state->tx_list, tx, next);
        IRCTransactionFree(tx, irc_state);
    }
    SCFree(irc_state);
}

/** \brief Function to check if transaction is ready to log.
 *  \internal
 *  \param tx - IRC Transaction. Cast to IRCTransaction *.
 *  \param direction - flow direction. Not used.
 *  \retval IRC_TX_STATE_READY (1) - If progress was done.
 *  \retval IRC_TX_STATE_NOT_READY (1) - If progress was not done yet.
 */
int IRCGetAlstateProgress(void *tx, uint8_t direction)
{
    IRCTransaction *irc_tx = (IRCTransaction *)tx;

    if ( irc_tx->request && !irc_tx->response &&
            SCMemcmp(irc_tx->request_cmd, IRC_CMD_NICK, 4) == 0) {
        return IRC_TX_STATE_READY;
    }

    if ( irc_tx->request && irc_tx->response) {
        return IRC_TX_STATE_READY;
    }

    return IRC_TX_STATE_NOT_READY;
}


/** \brief Get value for 'complete' status in IRC
 *  \internal
 *  \param direction - flow direction. Not used.
 *  \retval 1 - Always
 */
int IRCGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return 1;
}

/** \brief Registers patterns got application layer protocol detection.
 *  \internal
 *  \retval 0 - If all patterns are good.
 *  \retval -1 - If a pattern is bad. Should never happen, and it's a BUG.
 */
static int IRCRegisterPatternsForProtocolDetection(void)
{

    num_irc_commands = sizeof(irc_commands)/sizeof(IRCCommandName);

    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_IRC,
                ":", 1, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IRC,
                "NICK", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IRC,
                "LIST", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IRC,
                "QUIT", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IRC,
                "JOIN", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    return 0;
}

/** \brief Gets detect engine state from transaction.
 *  \internal
 *  \param vtx - Pointer to transaction. Cast to IRCTransaction *.
 *  \retval DetectEngineState * - The associated engine.
 */
static DetectEngineState *IRCGetTxDetectState(void *vtx)
{
    IRCTransaction *tx = (IRCTransaction *)vtx;
    return tx->de_state;
}

/** \brief Sets detect engine state for transaction.
 *  \internal
 *  \param state - pointer to state. Cast to IRCState *. Not used.
 *  \param vtx - Pointer to transaction. Cast to IRCTransaction *.
 *  \retval 0 - Always.
 */
static int IRCSetTxDetectState(void *state, void *vtx, DetectEngineState *s)
{
    IRCTransaction *tx = (IRCTransaction *)vtx;
    tx->de_state = s;
    return 0;
}

/** \brief Function to register the IRC protocol parsers and other functions.
*/
void RegisterIRCParsers(void)
{
    char *proto_name = "irc";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_IRC, proto_name);
        if (IRCRegisterPatternsForProtocolDetection() < 0) {
            SCLogInfo("Faled to register patterns fro %s protocol",
                    proto_name);
            return;
        }
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_IRC, IRCStateAlloc, IRCStateFree);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IRC, STREAM_TOSERVER, IRCParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IRC, STREAM_TOCLIENT, IRCParseResponse);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_IRC, STREAM_TOSERVER | STREAM_TOCLIENT) ;
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_IRC, NULL,
                IRCGetTxDetectState, IRCSetTxDetectState);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_IRC, IRCStateTransactionFree);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_IRC, IRCGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_IRC, IRCGetTxCnt);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_IRC, IRCGetTxLogged, IRCSetTxLogged);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_IRC, IRCGetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_IRC, IRCGetAlstateProgressCompletionStatus);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                "still on.", proto_name);
    }

#ifdef UNITTESTS
    //TODO
    //    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_IRC, IRCParserRegisterTests);
#endif
}
