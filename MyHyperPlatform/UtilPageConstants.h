#pragma once

// 本文件定义页表相关的常量
// 本文件只被 UtilInitializePageTableVariables 函数包含
// UtilInitializePageTableVariables 会初始化 g_UtilP*eBase 和 g_UtilP*iShift 和 g_UtilP*iMask 全局变量


// 就是定义虚拟地址的每一位的实际含义 
// 以下直接拷贝原注释

// Virtual Address Interpretation For Handling PTEs
//
// -- On x64
// Sign extension                     16 bits
// Page map level 4 selector           9 bits
// Page directory pointer selector     9 bits
// Page directory selector             9 bits
// Page table selector                 9 bits
// Byte within page                   12 bits
// 11111111 11111111 11111000 10000000 00000011 01010011 00001010 00011000
// ^^^^^^^^ ^^^^^^^^ ~~~~~~~~ ~^^^^^^^ ^^~~~~~~ ~~~^^^^^ ^^^^~~~~ ~~~~~~~~
// Sign extension    PML4      PDPT      PD        PT        Offset
//
// -- On x86(PAE)
// Page directory pointer selector     2 bits
// Page directory selector             9 bits
// Page table selector                 9 bits
// Byte within page                   12 bits
// 10 000011011 000001101 001001110101
// ^^ ~~~~~~~~~ ^^^^^^^^^ ~~~~~~~~~~~~
// PDPT PD      PT        Offset
//
// -- On x86 and ARM
// Page directory selector            10 bits
// Page table selector                10 bits
// Byte within page                   12 bits
// 1000001101 1000001101 001001110101
// ~~~~~~~~~~ ^^^^^^^^^^ ~~~~~~~~~~~~
// PD         PT         Offset
//
//                                   x64   x86(PAE)  x86   ARM
// Page map level 4 selector           9          -    -     -
// Page directory pointer selector     9          2    -     -
// Page directory selector             9          9   10    10
// Page table selector                 9          9   10    10
// Byte within page                   12         12   12    12
//
// 6666555555555544444444443333333333222222222211111111110000000000
// 3210987654321098765432109876543210987654321098765432109876543210
// ----------------------------------------------------------------
// aaaaaaaaaaaaaaaabbbbbbbbbcccccccccdddddddddeeeeeeeeeffffffffffff  x64
// ................................ccdddddddddeeeeeeeeeffffffffffff  x86(PAE)
// ................................ddddddddddeeeeeeeeeeffffffffffff  x86
// ................................ddddddddddeeeeeeeeeeffffffffffff  ARM
//
// a = Sign extension, b = PML4, c = PDPT, d = PD, e = PT, f = Offset

#ifdef _AMD64_

// Base addresses of page structures. Use !pte to obtain them.
// 关于 PXE PPE PDE PTE 可以在 WRK中搜索 MmGetPhysicalAddress
// EPT的页表结构是十分类似正常的分页机制
static auto UtilPXEBase = 0xfffff6fb7dbed000ull;
static auto UtilPPEBase = 0xfffff6fb7da00000ull;
static auto UtilPDEBase = 0xfffff6fb40000000ull;
static auto UtilPTEBase = 0xfffff68000000000ull;

// Get the highest 25 bits
static const auto UtilPXIShift = 39ull;

// Get the highest 34 bits
static const auto UtilPPIShift = 30ull;

// Get the highest 43 bits
static const auto UtilPDIShift = 21ull;

// Get the highest 52 bits
static const auto UtilPTIShift = 12ull;

// Use  9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
static const auto UtilPXIMask = 0x1ffull;

// Use 18 bits; 0b0000_0000_0000_0000_0011_1111_1111_1111_1111
static const auto UtilPPIMask = 0x3ffffull;

// Use 27 bits; 0b0000_0000_0111_1111_1111_1111_1111_1111_1111
static const auto UtilPDIMask = 0x7ffffffull;

// Use 36 bits; 0b1111_1111_1111_1111_1111_1111_1111_1111_1111
static const auto UtilPTIMask = 0xfffffffffull;

#elif defined(_X86_)

// Base addresses of page structures. Use !pte to obtain them.
static auto UtilPDEBase = 0xc0300000;
static auto UtilPTEBase = 0xc0000000;

// Get the highest 10 bits
static const auto UtilPDIShift = 22;

// Get the highest 20 bits
static const auto UtilPTIShift = 12;

// Use 10 bits; 0b0000_0000_0000_0000_0000_0000_0011_1111_1111
static const auto UtilPDIMask = 0x3ff;

// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
static const auto UtilPTIMask = 0xfffff;

// unused but defined to compile without ifdef

static auto UtilPXEBase = 0;
static auto UtilPPEBase = 0;
static const auto UtilPXIShift = 0;
static const auto UtilPPIShift = 0;
static const auto UtilPXIMask = 0;
static const auto UtilPPIMask = 0;

#endif


// Base addresses of page structures. Use !pte to obtain them.
static const auto UtilPDEBasePAE = 0xc0600000;
static const auto UtilPTEBasePAE = 0xc0000000;

// Get the highest 11 bits
static const auto UtilPDIShiftPAE = 21;

// Get the highest 20 bits
static const auto UtilPTIShiftPAE = 12;

// Use 11 bits; 0b0000_0000_0000_0000_0000_0000_0111_1111_1111
static const auto UtilPDIMaskPAE = 0x7ff;

// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
static const auto UtilPTIMaskPAE = 0xfffff;
