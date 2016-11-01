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
 */

#ifndef __APP_LAYER_IRC_H__
#define __APP_LAYER_IRC_H__

typedef struct IRCClient_ {
    int authenticated;
    int quitted;
    uint8_t *user;
    uint8_t *nick;
    size_t num_bad_cmds;
} IRCClient;

typedef struct IRCServer_ {
    char *hostname;
} IRCServer;

enum {
    IRC_TX_STATE_NOT_READY = 0,
    IRC_TX_STATE_READY = 1
};

typedef struct IRCTransaction_ {
    uint16_t tx_num;                    /**< internal: id */
    char *request;                      /**< irc client full request */
    uint8_t request_len;                /**< irc client request len */
    char *request_cmd;                  /**< irc client command */
    char *request_cmd_line;             /**< irc client command line*/
    char *response;                     /**< irc server response */
    uint8_t response_len;               /**< irc server response len */
    char *response_cmd_line;            /**< irc server response code/command line */
    uint32_t logged;                    /**< flags for loggers done logging */
    uint8_t bad_cmd;                    /**< irc command */
    DetectEngineState *de_state;	/** < the detection engine state */
    TAILQ_ENTRY(IRCTransaction_) next;	/**< the next transaction */
} IRCTransaction;

typedef struct IRCState_ {
    IRCTransaction *curr_tx;
    IRCServer srv;
    IRCClient cli;
    TAILQ_HEAD(_list, IRCTransaction_) tx_list;  /**< transaction list */
    uint64_t transaction_max;
} IRCState;

void *IRCGetTx(void *alstate, uint64_t tx_id);
void RegisterIRCParsers(void);
//TODO: void IRCParserRegisterTests(void);

#endif /* __APP_LAYER_IRC_H__ */

