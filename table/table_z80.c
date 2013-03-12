#include <stdio.h>
#include <stdlib.h>
#include "table_z80.h"

// http://search.cpan.org/~pscust/Asm-Z80-Table-0.02/lib/Asm/Z80/Table.pm
// http://wikiti.brandonw.net/index.php?title=Z80_Instruction_Set
// http://nemesis.lonestar.org/computers/tandy/software/apps/m4/qd/opcodes.html

struct _table_z80 table_z80[] =
{
  { "adc", 0x88, 0xf8, OP_A_REG8 },
  { "add", 0x80, 0xf8, OP_A_REG8 },
  { "ld", 0x78, 0xf8, OP_A_REG8 },
  { "sbc", 0x98, 0xf8, OP_A_REG8 },

  { "adc", 0xdd8c, 0xdffe, OP_A_REG_IHALF },
  { "add", 0xdd84, 0xdffe, OP_A_REG_IHALF },
  { "ld", 0xdd5c, 0xdffe, OP_A_REG_IHALF },
  { "sbc", 0xdd9c, 0xdffe, OP_A_REG_IHALF },

  { "adc", 0xdd8e, 0xdfff, OP_A_INDEX },
  { "add", 0xdd86, 0xdfff, OP_A_INDEX },
  { "ld", 0xdd7e, 0xdfff, OP_A_INDEX },
  { "sbc", 0xdd9e, 0xdfff, OP_A_INDEX },

  { "adc", 0xce, 0xff, OP_A_NUMBER8 },
  { "add", 0xc6, 0xff, OP_A_NUMBER8 },
  { "ld", 0x3d, 0xff, OP_A_NUMBER8 },
  { "sbc", 0xde, 0xff, OP_A_NUMBER8 },

  { "adc", 0xed4a, 0xffcf, OP_HL_REG16_2 },
  { "add", 0x09, 0xcf, OP_HL_REG16_1 },
  { "sbc", 0xed42, 0xffcf, OP_HL_REG16_2 },

  { "and", 0xa0, 0xf8, OP_REG8 },
  { "cp", 0xb8, 0xf8, OP_REG8 },
  { "or", 0xb0, 0xf8, OP_REG8 },
  { "sub", 0x90, 0xf8, OP_REG8 },
  { "xor", 0xa8, 0xf8, OP_REG8 },



  { "rl", 0xcb10, 0xfff8, OP_REG8_CB },
  { "rlc", 0xcb00, 0xfff8, OP_REG8_CB },
  { "rr", 0xcb18, 0xfff8, OP_REG8_CB },
  { "rrc", 0xcb08, 0xfff8, OP_REG8_CB },
  { "sla", 0xcb20, 0xfff8, OP_REG8_CB },
  //{ "sli", 0x30, OP_REG8_CB },
  { "sll", 0xcb30, 0xfff8, OP_REG8_CB },
  { "sra", 0xcb28, 0xfff8, OP_REG8_CB },
  { "srl", 0xcb38, 0xfff8, OP_REG8_CB },

  //{ "dec", 0x38, OP_REG8 },
  //{ "inc", 0x38, OP_REG8 },

  { NULL, 0x00, OP_NONE },
};

