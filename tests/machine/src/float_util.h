#ifndef FLOAT_UTIL_H
#define FLOAT_UTIL_H

#define TEST_FP_OP1_RM_S( testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  flw f0, 0(a0); \
  lw  a3, 4(a0); \
  inst f3, f0, rm; \
  fmv.x.s a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 2; \
  test_ ## testnum ## _data: \
  .float val1; \
  .float result; \
  .popsection

#define TEST_FP_OP1_RM_D( testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  fld f0, 0(a0); \
  ld  a3, 8(a0); \
  inst f3, f0, rm; \
  fmv.x.d a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double val1; \
  .double result; \
  .popsection

#define TEST_FP_OP2_RM_S( testnum, inst, flags, result, val1, val2, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  flw f0, 0(a0); \
  flw f1, 4(a0); \
  lw  a3, 8(a0); \
  inst f3, f0, f1, rm; \
  fmv.x.s a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 2; \
  test_ ## testnum ## _data: \
  .float val1; \
  .float val2; \
  .float result; \
  .popsection

#define TEST_FP_OP2_RM_D( testnum, inst, flags, result, val1, val2, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  fld f0, 0(a0); \
  fld f1, 8(a0); \
  ld  a3, 16(a0); \
  inst f3, f0, f1, rm; \
  fmv.x.d a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double val1; \
  .double val2; \
  .double result; \
  .popsection

#define TEST_FP_OP3_RM_S( testnum, inst, flags, result, val1, val2, val3, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  flw f0, 0(a0); \
  flw f1, 4(a0); \
  flw f2, 8(a0); \
  lw  a3, 12(a0); \
  inst f3, f0, f1, f2, rm; \
  fmv.x.s a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 2; \
  test_ ## testnum ## _data: \
  .float val1; \
  .float val2; \
  .float val3; \
  .float result; \
  .popsection

#define TEST_FP_OP3_RM_D( testnum, inst, flags, result, val1, val2, val3, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  fld f0, 0(a0); \
  fld f1, 8(a0); \
  fld f2, 16(a0); \
  ld  a3, 24(a0); \
  inst f3, f0, f1, f2, rm; \
  fmv.x.d a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double val1; \
  .double val2; \
  .double val3; \
  .double result; \
  .popsection

#define TEST_INT_FP_OP_RM_S( testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  lw  a3, 0(a0); \
  li  a0, val1; \
  inst f0, a0, rm; \
  fmv.x.s a0, f0; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 2; \
  test_ ## testnum ## _data: \
  .float result; \
  .popsection

#define TEST_INT_FP_OP_RM_D( testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  ld  a3, 0(a0); \
  li  a0, val1; \
  inst f0, a0, rm; \
  fmv.x.d a0, f0; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double result; \
  .popsection

#define TEST_INT_FP_OP_NORM_D( testnum, inst, flags, result, val1) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  ld  a3, 0(a0); \
  li  a0, val1; \
  inst f0, a0; \
  fmv.x.d a0, f0; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double result; \
  .popsection

#define TEST_FP_INT_OP_WORD_RM_S(testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  lw  a3, 0(a0); \
  flw f0, 4(a0); \
  inst a0, f0, rm; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 2; \
  test_ ## testnum ## _data: \
  .word result; \
  .float val1; \
  .popsection

#define TEST_FP_INT_OP_WORD_RM_D(testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  fld f0, 0(a0); \
  lw  a3, 8(a0); \
  inst a0, f0, rm; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double val1; \
  .word result; \
  .popsection

#define TEST_FP_INT_OP_DWORD_RM_S(testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  ld  a3, 0(a0); \
  flw f0, 8(a0); \
  inst a0, f0, rm; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .dword result; \
  .float val1; \
  .popsection

#define TEST_FP_INT_OP_DWORD_RM_D(testnum, inst, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  ld  a3, 0(a0); \
  fld f0, 8(a0); \
  inst a0, f0, rm; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .dword result; \
  .double val1; \
  .popsection

#define TEST_FCVT_D_S_RM( testnum, flags, result, val1 ) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  ld  a3, 0(a0); \
  flw f0, 8(a0); \
  fcvt.d.s f3, f0; \
  fmv.x.d a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double result; \
  .float val1; \
  .popsection

#define TEST_FCVT_S_D_RM( testnum, flags, result, val1, rm) \
test_ ## testnum: \
  li  TESTNUM, testnum; \
  la  a0, test_ ## testnum ## _data ;\
  fld f0, 0(a0); \
  lw  a3, 8(a0); \
  fcvt.s.d f3, f0; \
  fmv.x.s a0, f3; \
  fsflags a1, x0; \
  li a2, flags; \
  bne a0, a3, fail; \
  bne a1, a2, fail; \
  .pushsection .data; \
  .align 3; \
  test_ ## testnum ## _data: \
  .double val1; \
  .float result; \
  .popsection

#endif
