/**
 *  naken_asm assembler.
 *  Author: Michael Kohn
 *   Email: mike@mikekohn.net
 *     Web: http://www.mikekohn.net/
 * License: GPLv3
 *
 * Copyright 2010-2018 by Michael Kohn
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "asm/1802.h"
#include "asm/common.h"
#include "common/assembler.h"
#include "common/tokens.h"
#include "common/eval_expression.h"
#include "table/1802.h"

int parse_instruction_1802(struct _asm_context *asm_context, char *instr)
{
  char instr_case_mem[TOKENLEN];
  char *instr_case = instr_case_mem;
  char token[TOKENLEN];
  int token_type;
  int len = -1;
  int n;

  lower_copy(instr_case, instr);

  n = 0;

  while(table_1802[n].instr != NULL)
  {
    if (strcmp(table_1802[n].instr, instr_case) == 0)
    {
      switch(table_1802[n].type)
      {
        case RCA1802_OP_NONE:
        {
          add_bin8(asm_context, table_1802[n].opcode, IS_OPCODE);
          len = 1;
          break;
        }
        case RCA1802_OP_REG:
        {
          int reg = -1;

          token_type = tokens_get(asm_context, token, TOKENLEN);

          if (token_type == TOKEN_NUMBER)
          {
            reg = atoi(token);
            if (reg < 0 || reg > 15) { reg = -1; }
          }
            else
          if (token[1] == 0)
          {
            if (token[0] >= 'a' && token[0] <= 'f')
            {
              reg = (token[0] - 'a') + 10;
            }
              else
            if (token[0] >= 'A' && token[0] <= 'F')
            {
              reg = (token[0] - 'A') + 10;
            }
          }

          if (reg == -1)
          {
            print_error_unexp(token, asm_context);
            return -1;
          }

          add_bin8(asm_context, table_1802[n].opcode | reg, IS_OPCODE);
          len = 1;
          break;
        }
        case RCA1802_OP_NUM_1_TO_7:
        {
          int num = -1;

          tokens_get(asm_context, token, TOKENLEN);

          if (token[1] == 0 && token[0] >= '1' && token[0] <= '7')
          {
            num = token[0] - '0';
          }

          if (num == -1)
          {
            print_error_unexp(token, asm_context);
            return -1;
          }

          add_bin8(asm_context, table_1802[n].opcode | num, IS_OPCODE);
          len = 1;
          break;
        }
        case RCA1802_OP_IMMEDIATE:
        case RCA1802_OP_BRANCH:
        case RCA1802_OP_LONG_BRANCH:
        {
          int num = 0;

          if (asm_context->pass == 1)
          {
            eat_operand(asm_context);
          }
            else
          {
            if (eval_expression(asm_context, &num) != 0)
            {
              print_error_illegal_expression(instr, asm_context);
              return -1;
            }
          }

          if (table_1802[n].type == RCA1802_OP_IMMEDIATE)
          {
            if (num < -128 || num > 255)
            {
              print_error_range("Immediate", -128, 255, asm_context);
              return -1;
            }

            add_bin8(asm_context, table_1802[n].opcode, IS_OPCODE);
            add_bin8(asm_context, num & 0xff, IS_OPCODE);
            len = 2;
            break;
          }
            else
          if (table_1802[n].type == RCA1802_OP_BRANCH)
          {
            if ((num >> 8) != (asm_context->address >> 8))
            {
              print_error("Branch address must be on the the same page.\n", asm_context);
              return -1;
            }

            add_bin8(asm_context, table_1802[n].opcode, IS_OPCODE);
            add_bin8(asm_context, num & 0xff, IS_OPCODE);
            len = 2;
            break;
          }
            else
          if (table_1802[n].type == RCA1802_OP_LONG_BRANCH)
          {
            if (num < 0 || num > 0xffff)
            {
              print_error_range("Address", 0, 0xffff, asm_context);
              return -1;
            }

            add_bin8(asm_context, table_1802[n].opcode, IS_OPCODE);
            add_bin8(asm_context, (num >> 8) & 0xff, IS_OPCODE);
            add_bin8(asm_context, num & 0xff, IS_OPCODE);
            len = 2;
            break;
          }

        }
        default:
          break;
      }

      break;
    }

    n++;
  }

  if (len == -1)
  {
    print_error_unknown_instr(instr, asm_context);
    return -1;
  }

  token_type = tokens_get(asm_context, token, TOKENLEN);

  if (token_type != TOKEN_EOL && token_type != TOKEN_EOF)
  {
    print_error_unexp(token, asm_context);
    return -1;
  }

  return len;
}

