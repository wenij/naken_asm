/**
 *  naken_asm assembler.
 *  Author: Michael Kohn
 *   Email: mike@mikekohn.net
 *     Web: http://www.mikekohn.net/
 * License: GPLv3
 *
 * Copyright 2010-2021 by Michael Kohn
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#include "asm/8051.h"
#include "asm/common.h"
#include "common/assembler.h"
#include "common/tokens.h"
#include "common/eval_expression.h"
#include "table/8051.h"

enum
{
  OPERAND_REG,
  OPERAND_AT_REG,
  OPERAND_A,
  OPERAND_C,
  OPERAND_AB,
  OPERAND_DPTR,
  OPERAND_AT_A_PLUS_DPTR,
  OPERAND_AT_A_PLUS_PC,
  OPERAND_AT_DPTR,
  OPERAND_DATA,
  OPERAND_NUM,
  OPERAND_SLASH_BIT_ADDRESS,
  OPERAND_BIT_ADDRESS,
};

struct _operand
{
  int value;
  int type;
};

struct _address_map
{
  const char *name;
  uint8_t address;
  uint8_t is_bit_addressable;
};

static struct _address_map address_map[] =
{
  { "B",      0xf0, 1 },
  { "ACC",    0xe0, 1 },
  { "PSW",    0xd0, 1 },
  { "T2CON",  0xc8, 0 },
  { "T2MOD",  0xc9, 0 },
  { "RCAP2L", 0xca, 0 },
  { "RCAP2H", 0xcb, 0 },
  { "TL2",    0xcc, 0 },
  { "TH2",    0xcd, 0 },
  { "IP",     0xb8, 1 },
  { "P3",     0xb0, 1 },
  { "IE",     0xa8, 1 },
  { "P2",     0xa0, 1 },
  { "AUXR1",  0xa2, 0 },
  { "WDTRST", 0xa6, 0 },
  { "SCON",   0x98, 1 },
  { "SBUF",   0x99, 0 },
  { "P1",     0x90, 1 },
  { "TCON",   0x88, 1 },
  { "TMOD",   0x89, 0 },
  { "TL0",    0x8a, 0 },
  { "TL1",    0x8b, 0 },
  { "TH0",    0x8c, 0 },
  { "TH1",    0x8d, 0 },
  { "AUXR",   0x8e, 0 },
  { "P0",     0x80, 1 },
  { "SP",     0x81, 0 },
  { "DPL",    0x82, 0 },
  { "DPH",    0x83, 0 },
  { "DP0L",   0x82, 0 },
  { "DP0H",   0x83, 0 },
  { "DP1L",   0x84, 0 },
  { "DP1H",   0x85, 0 },
  { "PCON",   0x87, 0 },
};

static struct _address_map address_map_psw[] =
{
  { "CY",  0xd7 },
  { "AC",  0xd6 },
  { "F0",  0xd5 },
  { "RS1", 0xd4 },
  { "RS0", 0xd3 },
  { "OV",  0xd2 },
  { "UD",  0xd1 },
  { "P",   0xd0 },
};

static int get_register_8051(char *token)
{
  if (token[0] != 'r' && token[0] != 'R') { return -1; }
  if (token[1] >= '0' && token[1] <= '7' && token[2] == 0)
  {
    return token[1] - '0';
  }

  return -1;
}

static int get_bit_address(
  struct _asm_context *asm_context,
  int *num,
  uint8_t *is_bit_address)
{
  char token[TOKENLEN];
  int token_type;

  token_type = tokens_get(asm_context, token, TOKENLEN);
  if (token_type != TOKEN_NUMBER)
  {
    tokens_push(asm_context, token, token_type);
    return 0;
  }

  int bit = atoi(token);
  if (bit < 0 || bit > 7)
  {
    tokens_push(asm_context, token, token_type);
    return 0;
  }

  if (*num < 0x20 || *num > 0x2f)
  {
    print_error_range("Bit Address", 0x20, 0x3f, asm_context);
    return -1;
  }

  *num -= 0x20;
  *num = (*num << 3) | bit;

  *is_bit_address = 1;

  return 0;
}

static int get_bit_address_mapped(
  struct _asm_context *asm_context,
  int *num,
  uint8_t *is_bit_address)
{
  char token[TOKENLEN];
  int token_type;

  token_type = tokens_get(asm_context, token, TOKENLEN);
  if (token_type != TOKEN_NUMBER)
  {
    tokens_push(asm_context, token, token_type);
    return 0;
  }

  int bit = atoi(token);
  if (bit < 0 || bit > 7)
  {
    tokens_push(asm_context, token, token_type);
    return 0;
  }

  *num += bit;
  *is_bit_address = 1;

  return 0;
}

static int get_bit_address_alias(const char *token)
{
  int n;

  for (n = 0; n < sizeof(address_map_psw) / sizeof(struct _address_map); n++)
  {
    if (strcasecmp(token, address_map_psw[n].name) == 0)
    {
      return address_map_psw[n].address;
    }
  }

  return -1;
}

static int get_address(
  struct _asm_context *asm_context,
  int *num,
  uint8_t *is_bit_address)
{
  char token[TOKENLEN];
  int token_type;
  int n;

  *is_bit_address = 0;

  token_type = tokens_get(asm_context, token, TOKENLEN);

  for (n = 0; n < sizeof(address_map) / sizeof(struct _address_map); n++)
  {
    if (strcasecmp(token, address_map[n].name) == 0)
    {
      *num = address_map[n].address;

      if (address_map[n].is_bit_addressable == 1)
      {
        char token[TOKENLEN];
        int token_type;

        token_type = tokens_get(asm_context, token, TOKENLEN);
        if (IS_NOT_TOKEN(token, '.'))
        {
          tokens_push(asm_context, token, token_type);
          return 0;
        }

        return get_bit_address_mapped(asm_context, num, is_bit_address);
      }

      return 0;
    }
  }

  *num = get_bit_address_alias(token);

  if (*num != -1)
  {
    *is_bit_address = 1;
    return 0;
  }

  tokens_push(asm_context, token, token_type);

  if (eval_expression(asm_context, num) != 0)
  {
    return -1;
  }

  token_type = tokens_get(asm_context, token, TOKENLEN);
  if (IS_NOT_TOKEN(token, '.'))
  {
    tokens_push(asm_context, token, token_type);
    return 0;
  }

  return get_bit_address(asm_context, num, is_bit_address);
}

int parse_directive_8051(struct _asm_context *asm_context, const char *token1)
{
		char token[TOKENLEN];
		char name[TOKENLEN];

		int num;
		int token_type;

		if (strcasecmp(token1, "bit") == 0)
		{
		  asm_context->ignore_symbols = 1;
		  token_type = tokens_get(asm_context, name, TOKENLEN);
		  asm_context->ignore_symbols = 0;

			if (token_type == TOKEN_EOL || token_type == TOKEN_EOF)
			{
					print_error_unexp(token, asm_context);
					return -1;
			}

			if (expect_token(asm_context, '=') != 0) { return -1; }

			token_type = tokens_get(asm_context, token, TOKENLEN);
			tokens_push(asm_context, token, token_type);
			if( token_type == TOKEN_STRING ) {
					uint8_t is_bit_address=0;

					if (get_address(asm_context, &num, &is_bit_address) == -1)
					{
							return -1;
					}
			}else {
					if (eval_expression(asm_context, &num) == -1)
					{
							print_error("set expects an address", asm_context);
							return -1;
					}

					token_type = tokens_get(asm_context, token, TOKENLEN);
					if( token_type == TOKEN_SYMBOL && token[0]=='.' && token[1]==0) {
							token_type = tokens_get(asm_context, token, TOKENLEN);
							if(token_type!=TOKEN_NUMBER) {
									print_error_unexp(token, asm_context);
									return -1;
							}
							int bit = atol(token);
							if ( bit > 7 || bit < 0) {
									print_error_range(token, 0,7,asm_context);
									return -1;
							}
							/* calculate bit address */
							if (num < 0x20 || (num > 0x2f && num < 0x80) || (num > 0x80 && (num % 8 !=0)) || num > 0xff) {
									printf("Error: None bit address '0x%02x' at %s:%d.\n",num,asm_context->tokens.filename,
																	asm_context->tokens.line);
									return -1;
							}
							/* calculate the bit_address */
							if ( num >= 0x80 ) {
									num = num + bit;
							}else {
									num = (( num - 0x20) << 3) + bit;
							}
					}else if (token_type != TOKEN_EOL && token_type != TOKEN_EOF &&
										 token_type == TOKEN_NUMBER)
					{
							print_error_unexp(token, asm_context);
							return -1;
					}
			}
			// REVIEW - should num be divided by bytes_per_address for dsPIC and avr8?
			symbols_set(&asm_context->symbols, name, num);

			asm_context->tokens.line++;

			return 0;
		}

		return 1;
}

int find_symbol_to_dec(struct _asm_context *asm_context,const int ck_address)
{
		struct _symbols *symbols = &(asm_context->symbols);
		struct _memory_pool *memory_pool = symbols->memory_pool;
		int ptr;

		// Check local scope.
		if (symbols->in_scope != 0)
		{
				while(memory_pool != NULL)
				{
						ptr = 0;

						while(ptr < memory_pool->ptr)
						{
								struct _symbols_data *symbols_data =
										(struct _symbols_data *)(memory_pool->buffer + ptr);

								if (symbols->current_scope == symbols_data->scope &&
												symbols_data->address > ck_address )
								{
										//printf("fixed symbol(%s) = %04x --> %04x \n",symbols_data->name,symbols_data->address ,symbols_data->address -1 );
										symbols_data->address = symbols_data->address - 1 ;
								}

								ptr += symbols_data->len + sizeof(struct _symbols_data);
						}

						memory_pool = memory_pool->next;
				}

				memory_pool = symbols->memory_pool;
		}

		// Check global scope.
		while(memory_pool != NULL)
		{
				ptr = 0;

				while(ptr < memory_pool->ptr)
				{
						struct _symbols_data *symbols_data =
								(struct _symbols_data *)(memory_pool->buffer + ptr);

						if (symbols_data->scope == 0 && symbols_data->address > ck_address )
						{
								//printf("fixed symbol(%s) = %04x --> %04x \n",symbols_data->name,symbols_data->address ,symbols_data->address -1 );
								symbols_data->address = symbols_data->address - 1 ;
						}

						ptr += symbols_data->len + sizeof(struct _symbols_data);
				}

				memory_pool = memory_pool->next;
		}

		return 0;
}

int parse_instruction_8051(struct _asm_context *asm_context, char *instr)
{
  char instr_case_mem[TOKENLEN]={0};
  char *instr_case = instr_case_mem;
  char token[TOKENLEN];
  struct _operand operands[3];
  uint8_t is_bit_address;
  int operand_count = 0;
  int token_type;
  int matched = 0;
  int num, n, r;
  int count = 1;
  int optimize_try=1;

  lower_copy(instr_case, instr);
  memset(&operands, 0, sizeof(operands));

  while (1)
  {
    token_type = tokens_get(asm_context, token, TOKENLEN);

    if (token_type == TOKEN_EOL || token_type == TOKEN_EOF)
    {
      if (operand_count != 0)
      {
        print_error_unexp(token, asm_context);
        return -1;
      }
      break;
    }

    num = get_register_8051(token);

    if (num != -1)
    {
      operands[operand_count].type = OPERAND_REG;
      operands[operand_count].value = num;
    }
      else
    if (token_type == TOKEN_STRING &&
       (IS_TOKEN(token,'A') || IS_TOKEN(token,'a')))
    {
      operands[operand_count].type = OPERAND_A;
    }
      else
    if (token_type == TOKEN_STRING &&
       (IS_TOKEN(token,'C') || IS_TOKEN(token,'c')))
    {
      operands[operand_count].type = OPERAND_C;
    }
      else
    if (strcasecmp(token, "ab") == 0)
    {
      operands[operand_count].type = OPERAND_AB;
    }
      else
    if (strcasecmp(token, "dptr") == 0)
    {
      operands[operand_count].type = OPERAND_DPTR;
    }
      else
    if (IS_TOKEN(token,'@'))
    {
      token_type = tokens_get(asm_context, token, TOKENLEN);
      num = get_register_8051(token);
      if (num != -1)
      {
        operands[operand_count].type = OPERAND_AT_REG;
        operands[operand_count].value = num;
      }
        else
      if (strcasecmp(token, "dptr") == 0)
      {
        operands[operand_count].type = OPERAND_AT_DPTR;
      }
        else
      if (token_type == TOKEN_STRING && strcasecmp(token, "a") == 0)
      {
        do
        {
          token_type = tokens_get(asm_context, token, TOKENLEN);
          if (IS_NOT_TOKEN(token,'+')) break;
          token_type = tokens_get(asm_context, token, TOKENLEN);
          if (strcasecmp(token, "dptr") == 0)
          {
            operands[operand_count].type = OPERAND_AT_A_PLUS_DPTR;
          }
            else
          if (strcasecmp(token, "pc") == 0)
          {
            operands[operand_count].type = OPERAND_AT_A_PLUS_PC;
          }
        } while (0);

        if (operands[operand_count].type == 0)
        {
          print_error_unexp(token, asm_context);
          return -1;
        }
      }
        else
      {
        print_error_unexp(token, asm_context);
        return -1;
      }
    }
      else
    if (token_type == TOKEN_POUND)
    {
			int extra_keyword=0;

			token_type = tokens_get(asm_context, token, TOKENLEN);
			if (strcasecmp(token,"high")==0) { // check keyword 'high'
					extra_keyword = 1;
			}else if(strcasecmp(token,"low")==0) { // check keyword 'low'
					extra_keyword = 2;
			}
			else
			{
					tokens_push(asm_context, token, token_type); // others, push back
			}

      if (eval_expression(asm_context, &num) != 0)
      {
        if (asm_context->pass == 1)
        {
          eat_operand(asm_context);
          num = 0;
        }
          else
        {
          print_error_illegal_expression(instr, asm_context);
          return -1;
        }
      }
			/* process keyword */
			if ( extra_keyword == 1) {
				num = (num >> 8) & 0xff ;
			}else if (extra_keyword == 2) {
				num = num & 0xff ;
			}

      operands[operand_count].type = OPERAND_DATA;
      operands[operand_count].value = num;
    }
      else
    if (IS_TOKEN(token,'/'))
    {
      if (get_address(asm_context, &num, &is_bit_address) == -1)
      {
        return -1;
      }

      operands[operand_count].value = num;
      operands[operand_count].type = OPERAND_SLASH_BIT_ADDRESS;
    }
      else
    {
      tokens_push(asm_context, token, token_type);

      if (asm_context->pass == 1)
      {
        operands[operand_count].type = OPERAND_NUM;
        operands[operand_count].value = 0;

        // Ignore tokens for this operand unless it's a . or a flag.
        while (1)
        {
          token_type = tokens_get(asm_context, token, TOKENLEN);

          if (IS_TOKEN(token, ',') ||
              token_type == TOKEN_EOL ||
              token_type == TOKEN_EOF)
          {
            break;
          }
            else
          if (IS_TOKEN(token, '.') || get_bit_address_alias(token) != -1)
          {
            operands[operand_count].type = OPERAND_BIT_ADDRESS;
          }
        }

        tokens_push(asm_context, token, token_type);
      }
        else
      {
        if (get_address(asm_context, &num, &is_bit_address) == -1)
        {
          return -1;
        }

        if (is_bit_address == 0)
        {
          operands[operand_count].type = OPERAND_NUM;
        }
          else
        {
          operands[operand_count].type = OPERAND_BIT_ADDRESS;
        }

        operands[operand_count].value = num;
      }
    }

    operand_count++;
    token_type = tokens_get(asm_context, token, TOKENLEN);

    if (token_type == TOKEN_EOL) { break; }
    if (IS_NOT_TOKEN(token, ',') || operand_count == 3)
    {
      print_error_unexp(token, asm_context);
      return -1;
    }
  }

#ifdef DEBUG
printf("-----\n");
for (n = 0; n < operand_count; n++)
{
printf("[%d %d]", operands[n].type, operands[n].value);
}
printf("\n");
#endif
int run_optimize  = 0;
if (asm_context->optimize == 1 && asm_context->pass == 2 ) {
  //printf("instr = %s \n",  instr_case );
  if(strcmp(instr_case,"ljmp")==0 ) {
    //printf("(%d) change instr from %s to ajmp \n",asm_context->tokens.line,instr_case);
    strcpy(instr_case,"ajmp");
    run_optimize = 1;
    optimize_try ++ ; //  2
  }else if ( strcmp(instr_case,"lcall")==0 ) {
    //printf("(%d) change instr from %s to acall \n",asm_context->tokens.line,instr_case);
    strcpy(instr_case,"acall");
    run_optimize = 1;
    optimize_try ++ ; // 2
  }
}

do {
  if ( run_optimize ) {
    if (optimize_try == 1) {
       if(strcmp(instr_case,"ajmp")==0 ) {
          //printf("2nd try change instr from %s to ljmp \n",instr_case);
          strcpy(instr_case,"ljmp");
          run_optimize = 0;

       }else if ( strcmp(instr_case,"acall")==0 ) {
          //printf("2nd try change instr from %s to lcall \n",instr_case);
          strcpy(instr_case,"lcall");
          run_optimize = 0;
       }
    }
  }
  for (n = 0; n < 256; n++)
  {
    if (strcmp(table_8051[n].name, instr_case) == 0)
    {
      matched = 1;
      for (r = 0; r < 3; r++)
      {
        if (table_8051[n].op[r] == OP_NONE) { break; }

        switch(table_8051[n].op[r])
        {
          case OP_REG:
            if (operands[r].type != OPERAND_REG ||
                operands[r].value != table_8051[n].range) { r = 4; }
            break;
          case OP_AT_REG:
            if (operands[r].type != OPERAND_AT_REG ||
                operands[r].value != table_8051[n].range) { r = 4; }
            break;
          case OP_A:
            if (operands[r].type != OPERAND_A) { r = 4; }
            break;
          case OP_C:
            if (operands[r].type != OPERAND_C) { r = 4; }
            break;
          case OP_AB:
            if (operands[r].type != OPERAND_AB) { r = 4; }
            break;
          case OP_DPTR:
            if (operands[r].type != OPERAND_DPTR) { r = 4; }
            break;
          case OP_AT_A_PLUS_DPTR:
            if (operands[r].type != OPERAND_AT_A_PLUS_DPTR) { r = 4; }
            break;
          case OP_AT_A_PLUS_PC:
            if (operands[r].type != OPERAND_AT_A_PLUS_PC) { r = 4; }
            break;
          case OP_AT_DPTR:
            if (operands[r].type != OPERAND_AT_DPTR) { r = 4; }
            break;
          case OP_DATA_16:
            if (operands[r].type != OPERAND_DATA ||
                (operands[r].value < -32768 ||
                 operands[r].value > 0xffff)) { r = 4; }
            break;
          case OP_CODE_ADDR:
            if (operands[r].type != OPERAND_NUM ||
                (operands[r].value < 0 ||
                 operands[r].value > 0xffff)) { r = 4; }
            break;
          case OP_RELADDR:
            if (operands[r].type != OPERAND_NUM) { r = 4; }
            break;
          case OP_DATA:
            if (operands[r].type != OPERAND_DATA ||
                (operands[r].value < -128 ||
                 operands[r].value > 255)) { r = 4; }
            break;
          case OP_SLASH_BIT_ADDR:
            if (operands[r].type != OPERAND_SLASH_BIT_ADDRESS ||
                (operands[r].value < 0 ||
                 operands[r].value > 255)) { r = 4; }
            break;
          case OP_PAGE:
            if (((operands[r].value >> 8) & 7) == table_8051[n].range)
            {
              int high_bits = operands[r].value & 0xf800;
              int address = asm_context->address + 2;

              if (asm_context->pass == 1)
              {
                high_bits = address & 0xf800;
              }

              if (high_bits != (address & 0xf800))
              {
                if (optimize_try > 1) {
									//  printf(" OP_PAGE fail, need try \n");
                  r = 4;
                  break;
                }else {
                  print_error("Destination address outside 2k block.", asm_context);
                  return -1;
                }
              }
							if ( optimize_try > 1 && (operands[r].value >address)) {
									r = 4;
                  break;
							}
              // get matched ,assembly it
              if (optimize_try > 1) {
									if (asm_context->pass == 2 && asm_context->extra_context==0)  { /* only need fixed and show up in Pass 2 */
										if (asm_context->quiet_output == 0)
											printf("Optimize: %s at %s:%d \n", instr_case,
													 asm_context->tokens.filename,
													 asm_context->tokens.line);
										/* fixed the symbol behind this address */
										find_symbol_to_dec(asm_context,address);
										asm_context->memory.size -= 1;
									}
									optimize_try = 1;
              }
            }
              else
            {
              // r = 4 breaks out of the for loop.
              r = 4;
              break;
            }
            break;
          case OP_BIT_ADDR:
            if (operands[r].type != OPERAND_NUM &&
                operands[r].type != OPERAND_BIT_ADDRESS) { r = 4; }
            if (operands[r].value < 0 || operands[r].value > 255) { r = 4; }
            break;
          case OP_IRAM_ADDR:
            if (operands[r].type != OPERAND_NUM ||
                (operands[r].value < 0 ||
                 operands[r].value > 255)) { r = 4; }
            break;
          default:
            print_error_internal(asm_context, __FILE__, __LINE__);
            return -1;
        }
      }

      if (r == operand_count)
      {
        memory_write_inc(asm_context, n, asm_context->tokens.line);

        // Holy crap :(
        if (n == 0x85)
        {
          memory_write_inc(asm_context, operands[1].value & 0xff, asm_context->tokens.line);
          memory_write_inc(asm_context, operands[0].value & 0xff, asm_context->tokens.line);
          break;
        }

        for (r = 0; r < 3; r++)
        {
          if (table_8051[n].op[r] == OP_NONE) { break; }
          switch(table_8051[n].op[r])
          {
            case OP_DATA_16:
            case OP_CODE_ADDR:
            {
              uint16_t value = operands[r].value & 0xffff;
              memory_write_inc(asm_context, value >> 8, asm_context->tokens.line);
              memory_write_inc(asm_context, value & 0xff, asm_context->tokens.line);
              count += 2;
              break;
            }
            case OP_RELADDR:
            {
              num = operands[r].value - (asm_context->address + 1);
              if (asm_context->pass == 1) { num = 0; }

              if (num < -128 || num > 127)
              {
                print_error_range("Offset", -128, 127, asm_context);
                return -1;
              }

              memory_write_inc(asm_context, num & 0xff, asm_context->tokens.line);
              count++;
              break;
            }
            case OP_DATA:
            case OP_SLASH_BIT_ADDR:
            case OP_PAGE:
            case OP_BIT_ADDR:
            case OP_IRAM_ADDR:
            {
              memory_write_inc(asm_context, (uint8_t)operands[r].value & 0xff, asm_context->tokens.line);
              count++;
              break;
            }
          }
        }

        break;
      }

    }
  }
  //printf(" optimize_try = %d \n",optimize_try);
}while ( --optimize_try > 0);

  if (n == 256)
  {
    if (matched == 1)
    {
      print_error_unknown_operand_combo(instr, asm_context);
    }
      else
    {
      print_error_unknown_instr(instr, asm_context);
    }

    return -1;
  }

  return count;
}

