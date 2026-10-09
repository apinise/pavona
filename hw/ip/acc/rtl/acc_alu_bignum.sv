// Copyright lowRISC contributors (OpenTitan project).
// Copyright zeroRISC Inc.
// Modified by Authors of "Towards ML-KEM & ML-DSA on OpenTitan" (https://eprint.iacr.org/2024/1192).
// Copyright "Towards ML-KEM & ML-DSA on OpenTitan" Authors.
// Modified by Ruben Niederhagen and Hoang Nguyen Hien Pham - authors of
// "Improving ML-KEM & ML-DSA on OpenTitan - Efficient Multiplication Vector Instructions for OTBN"
// (https://eprint.iacr.org/2025/2028).
// Copyright Ruben Niederhagen and Hoang Nguyen Hien Pham.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

/**
 * ACC alu block for the bignum instruction subset
 *
 * This ALU supports all of the 'plain' arithmetic and logic bignum instructions, BN.MULQACC is
 * implemented in a separate block.
 *
 * One barrel shifter and two adders (X and Y) are implemented along with the logic operators
 * (AND,OR,XOR,NOT).
 *
 * The adders have 256-bit operands with a carry_in and optional invert on the second operand. This
 * can be used to implement subtraction (a - b == a + ~b + 1). BN.SUBB/BN.ADDC are implemented by
 * feeding in the carry flag as carry in rather than a fixed 0 or 1.
 *
 * The shifter takes a 512-bit input (to implement BN.RSHI, concatenate and right shift) and shifts
 * right by up to 256-bits. The lower (256-bit) half of the input and output can be reversed to
 * allow left shift implementation.  There is no concatenate and left shift instruction so reversing
 * isn't required over the full width.
 *
 * The dataflow between the adders and shifter is in the diagram below. This arrangement allows the
 * implementation of the pseudo-mod (BN.ADDM/BN.SUBM) instructions in a single cycle whilst
 * minimising the critical path. The pseudo-mod instructions do not have a shifted input so X can
 * compute the initial add/sub and Y computes the pseudo-mod result. For all other add/sub
 * operations Y computes the operation with one of the inputs supplied by the shifter and the other
 * from operand_a.
 *
 * Both adder X and the shifter get supplied with operand_a and operand_b from the operation_i
 * input. In addition the shifter gets a shift amount (shift_amt) and can use 0 instead of
 * operand_a. The shifter concatenates operand_a (or 0) and operand_b together before shifting with
 * operand_a in the upper (256-bit) half {operand_a/0, operand_b}. This allows the shifter to pass
 * through operand_b simply by not performing a shift.
 *
 * Blanking is employed on the ALU data paths. This holds unused data paths to 0 to reduce side
 * channel leakage. The lower-case 'b' on the digram below indicates points in the data path that
 * get blanked. Note that Adder X is never used in isolation, it is always combined with Adder Y so
 * there is no need for blanking between Adder X and Adder Y.
 *
 *      A       B       A   B
 *      |       |       |   |
 *      b       b       b   b   shift_amt
 *      |       |       |   |   |
 *    +-----------+   +-----------+
 *    |  Adder X  |   |  Shifter  |
 *    +-----------+   +-----------+
 *          |               |
 *          |----+     +----|
 *          |    |     |    |
 *      X result |     | Shifter result
 *               |     |
 *             A |     |
 *             | |     |     +-----------+
 *             b |     b +---|  MOD WSR  |
 *             | |     | |   +-----------+
 *           \-----/ \-----/
 *            \---/   \---/
 *              |       |
 *              |       |
 *            +-----------+
 *            |  Adder Y  |
 *            +-----------+
 *                  |
 *              Y result
 */


module acc_alu_bignum
  import acc_pkg::*;
#(
  // Enabling PQC hardware support with vector ISA extension
  parameter  bit AccPQCEn = 1'b1
) (
  input logic clk_i,
  input logic rst_ni,

  input  alu_bignum_operation_t operation_i,
  input  logic                  operation_valid_i,
  input  logic                  operation_commit_i, // used for SVAs only
  output logic [WLEN-1:0]       operation_result_o,

  input  alu_predec_bignum_t    alu_predec_bignum_i,

  input  logic [WLEN-1:0]       ispr_mod_no_intg_i,
  output logic                  mod_used_o,

  input  flags_t                selected_flags_i,
  output flags_t                adder_update_flags_o,
  output logic                  adder_update_flags_en_raw_o,
  output flags_t                logic_update_flags_o,
  output logic                  logic_update_flags_en_raw_o,

  output logic                  alu_predec_error_o
);
  // Localparam net widths base on PQC enable
  localparam int ADDY_LEN = (AccPQCEn) ? WLEN-1 : WLEN+1;
  localparam int ADDER_MSB_IDX = (AccPQCEn) ? WLEN-1 : WLEN;
  localparam int ADDER_LSB_IDX = (AccPQCEn) ? 0 : 1;

  // Tie unused ports to '0
  generate
    if (!AccPQCEn) begin : gen_unused_outputs
      // Tie off unused inputs
      logic unused_bits;
      assign unused_bits = ^{operation_i.trn_type, operation_i.vector_sel, operation_i.vector_type,
                             alu_predec_bignum_i.trn_type, alu_predec_bignum_i.vector_sel,
                             alu_predec_bignum_i.vector_type};
    end
  endgenerate

  logic [WLEN-1:0]   logical_res;
  logic [ADDY_LEN:0] adder_y_res;

  generate
    if (AccPQCEn) begin : gen_adder_y_res_pqc
      logic [15:0] adder_y_carry_out;
    end
  endgenerate

  //////////////////
  // Flags Update //
  //////////////////

  logic adder_carry;

  // Adder operations update all flags.
  generate
    if (AccPQCEn) begin : gen_adder_flags_pqc
      assign adder_carry = gen_adder_y_res_pqc.adder_y_carry_out[15];
    end else begin : gen_adder_flags
      assign adder_carry = adder_y_res[WLEN+1];
    end
  endgenerate

  assign adder_update_flags_o.C = (operation_i.op == AluOpBignumAdd ||
                                  operation_i.op == AluOpBignumAddc) ? adder_carry : ~adder_carry;
  assign adder_update_flags_o.M = adder_y_res[ADDER_MSB_IDX];
  assign adder_update_flags_o.L = adder_y_res[ADDER_LSB_IDX];
  assign adder_update_flags_o.Z = ~|adder_y_res[ADDER_MSB_IDX:ADDER_LSB_IDX];

  assign logic_update_flags_o.C = '0;
  assign logic_update_flags_o.M = logical_res[WLEN-1];
  assign logic_update_flags_o.L = logical_res[0];
  assign logic_update_flags_o.Z = ~|logical_res;

  /////////////
  // Shifter //
  /////////////

  logic [WLEN-1:0]   shifter_operand_a_blanked;
  logic [WLEN-1:0]   shifter_operand_b_blanked;
  logic [WLEN-1:0]   shifter_res, unused_shifter_out_upper;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_shifter_operand_a_blanker (
    .in_i (operation_i.operand_a),
    .en_i (alu_predec_bignum_i.shifter_a_en),
    .out_o(shifter_operand_a_blanked)
  );

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_shifter_operand_b_blanker (
    .in_i (operation_i.operand_b),
    .en_i (alu_predec_bignum_i.shifter_b_en),
    .out_o(shifter_operand_b_blanked)
  );

generate
  if (AccPQCEn) begin : gen_shifter_pqc
    logic [WLEN-1:0]   shifter_bignum_in_upper, shifter_bignum_in_lower;
    logic [WLEN-1:0]   shifter_bignum_in_lower_reverse;
    logic [WLEN*2-1:0] shifter_bignum_in;
    logic [WLEN*2-1:0] shifter_bignum_out;
    logic [WLEN-1:0]   shifter_bignum_out_lower_reverse;
    logic [WLEN-1:0]   shifter_bignum_res;
    logic [15:0]       shifter_vec_in [17];
    logic [15:0]       shifter_vec_in_orig [16];
    logic [15:0]       shifter_vec_in_reverse [16];
    logic [15:0]       shifter_vec_out [16];
    logic [31:0]       shifter_vec_tmp [16];
    logic [31:0]       shifter_vec_tmp_shifted [16];
    logic [15:0]       shifter_vec_out_reverse [16];
    logic [WLEN-1:0]   shifter_vec_res;
    logic              shifter_selvector_i;

    // BIGNUM SHIFTER
    // Operand A is only used for BN.RSHI, otherwise the upper input is 0. For all insns other
    // than BN.RHSI alu_predec_bignum_i.shifter_a_en will be 0, resulting in 0 for the upper input.
    assign shifter_bignum_in_upper = shifter_operand_a_blanked;
    assign shifter_bignum_in_lower = shifter_operand_b_blanked;

    for (genvar i = 0; i < WLEN; i++) begin : g_shifter_bignum_in_lower_reverse
      assign shifter_bignum_in_lower_reverse[i] = shifter_bignum_in_lower[WLEN-i-1];
    end

    assign shifter_bignum_in = {shifter_bignum_in_upper,
        alu_predec_bignum_i.shift_right ? shifter_bignum_in_lower
                                        : shifter_bignum_in_lower_reverse};

    assign shifter_bignum_out = shifter_bignum_in >> alu_predec_bignum_i.shift_amt;

      for (genvar i = 0; i < WLEN; i++) begin : g_shifter_bignum_out_lower_reverse
        assign shifter_bignum_out_lower_reverse[i] = shifter_bignum_out[WLEN-i-1];
      end

      assign shifter_bignum_res =
          alu_predec_bignum_i.shift_right ? shifter_bignum_out[WLEN-1:0]
                                          : shifter_bignum_out_lower_reverse;

      // VECTOR SHIFTER
      assign shifter_selvector_i = operation_i.vector_type[0];
      assign shifter_vec_in[16] = '0;
      // split into 16-bit chunks for vectorized shift
      for (genvar i=0; i<16; ++i) begin : g_shifter_vec
        assign shifter_vec_in_orig[i] = shifter_operand_b_blanked[i*16+:16];
        for (genvar j=0; j<WLEN/16; ++j) begin : g_shifter_vec_reverse_input
          assign shifter_vec_in_reverse[i][j] = shifter_vec_in_orig[i][WLEN/16-j-1];
        end
        assign shifter_vec_in[i] =
            alu_predec_bignum_i.shift_right ? shifter_vec_in_orig[i] : shifter_selvector_i ?
                shifter_vec_in_reverse[i] : (i % 2 == 1) ?
                    shifter_vec_in_reverse[i-1] : shifter_vec_in_reverse[i+1];

        // Shifter below either shifts as 16 or 32 bit vectors
        assign shifter_vec_tmp[i] = {shifter_vec_in[i+1], shifter_vec_in[i]};
        assign shifter_vec_tmp_shifted[i] = shifter_vec_tmp[i] >> alu_predec_bignum_i.shift_amt;
        assign shifter_vec_out[i] =
            (shifter_selvector_i | (i % 2 == 1)) ?
            (shifter_vec_in[i] >> alu_predec_bignum_i.shift_amt) :
            shifter_vec_tmp_shifted[i][15:0];

        for (genvar j=0; j<WLEN/16; ++j) begin : g_shifter_vec_reverse_output
          assign shifter_vec_out_reverse[i][j] =
              shifter_selvector_i ? shifter_vec_out[i][WLEN/16-j-1] : (i % 2 == 1) ?
                  shifter_vec_out[i-1][WLEN/16-j-1] : shifter_vec_out[i+1][WLEN/16-j-1];
        end
        assign shifter_vec_res[i*16+:16] =
            alu_predec_bignum_i.shift_right ? shifter_vec_out[i] : shifter_vec_out_reverse[i];
      end

      // SHIFTER RESULT
      assign shifter_res = (operation_i.op == acc_pkg::AluOpBignumShv) ? shifter_vec_res
                                                                        : shifter_bignum_res;

      // Only the lower WLEN bits of the shift result are returned.
      assign unused_shifter_out_upper = shifter_bignum_out[WLEN*2-1:WLEN];

    end else begin : gen_shifter
      logic [WLEN-1:0]   shifter_in_upper, shifter_in_lower, shifter_in_lower_reverse;
      logic [WLEN*2-1:0] shifter_in;
      logic [WLEN*2-1:0] shifter_out;
      logic [WLEN-1:0]   shifter_out_lower_reverse;

      // BIGNUM SHIFTER
      // Operand A is only used for BN.RSHI, otherwise the upper input is 0. For all instructions other
      // than BN.RHSI alu_predec_bignum_i.shifter_a_en will be 0, resulting in 0 for the upper input.
      assign shifter_in_upper = shifter_operand_a_blanked;
      assign shifter_in_lower = shifter_operand_b_blanked;

      for (genvar i = 0; i < WLEN; i++) begin : g_shifter_in_lower_reverse
        assign shifter_in_lower_reverse[i] = shifter_in_lower[WLEN-i-1];
      end

      assign shifter_in = {shifter_in_upper,
          alu_predec_bignum_i.shift_right ? shifter_in_lower : shifter_in_lower_reverse};

      assign shifter_out = shifter_in >> alu_predec_bignum_i.shift_amt;

      for (genvar i = 0; i < WLEN; i++) begin : g_shifter_out_lower_reverse
        assign shifter_out_lower_reverse[i] = shifter_out[WLEN-i-1];
      end

      assign shifter_res =
          alu_predec_bignum_i.shift_right ? shifter_out[WLEN-1:0] : shifter_out_lower_reverse;

      // Only the lower WLEN bits of the shift result are returned.
      assign unused_shifter_out_upper = shifter_out[WLEN*2-1:WLEN];

    end
  endgenerate

  ///////////////
  // Transpose //
  ///////////////
  generate
    if (AccPQCEn) begin : gen_trn_pqc
      logic [WLEN/16-1:0] trn_op0_16h [16];
      logic [WLEN/8-1:0]  trn_op0_8s  [8];
      logic [WLEN/4-1:0]  trn_op0_4d  [4];
      logic [WLEN/2-1:0]  trn_op0_2q  [2];

      logic [WLEN/16-1:0] trn_op1_16h [16];
      logic [WLEN/8-1:0]  trn_op1_8s  [8];
      logic [WLEN/4-1:0]  trn_op1_4d  [4];
      logic [WLEN/2-1:0]  trn_op1_2q  [2];

      logic [WLEN-1:0]    trn_res;

      for (genvar i=0; i<16; ++i) begin : g_trn_16h
        assign trn_op0_16h[i] = operation_i.operand_a[i*16+:16];
        assign trn_op1_16h[i] = operation_i.operand_b[i*16+:16];
      end

      for (genvar i=0; i<8; ++i) begin : g_trn_8s
        assign trn_op0_8s[i] = operation_i.operand_a[i*32+:32];
        assign trn_op1_8s[i] = operation_i.operand_b[i*32+:32];
      end

      for (genvar i=0; i<4; ++i) begin : g_trn_4d
        assign trn_op0_4d[i] = operation_i.operand_a[i*64+:64];
        assign trn_op1_4d[i] = operation_i.operand_b[i*64+:64];
      end

      for (genvar i=0; i<2; ++i) begin : g_trn_2q
        assign trn_op0_2q[i] = operation_i.operand_a[i*128+:128];
        assign trn_op1_2q[i] = operation_i.operand_b[i*128+:128];
      end

      always_comb begin
        case (operation_i.trn_type)
          trn1_16h: begin
            for (int i=0; i<8; ++i) begin
              trn_res[i*32+:32] = {trn_op1_16h[2*i],trn_op0_16h[2*i]};
            end
          end

          trn1_8s: begin
            for (int i=0; i<4; ++i) begin
              trn_res[i*64+:64] = {trn_op1_8s[2*i],trn_op0_8s[2*i]};
            end
          end

          trn1_4d: begin
            for (int i=0; i<2; ++i) begin
              trn_res[i*128+:128] = {trn_op1_4d[2*i],trn_op0_4d[2*i]};
            end
          end

          trn1_2q: begin
            for (int i=0; i<1; ++i) begin
              trn_res[i*256+:256] = {trn_op1_2q[2*i],trn_op0_2q[2*i]};
            end
          end

          trn2_16h: begin
            for (int i=0; i<8; ++i) begin
              trn_res[i*32+:32] = {trn_op1_16h[2*i+1],trn_op0_16h[2*i+1]};
            end
          end

          trn2_8s: begin
            for (int i=0; i<4; ++i) begin
              trn_res[i*64+:64] = {trn_op1_8s[2*i+1],trn_op0_8s[2*i+1]};
            end
          end

          trn2_4d: begin
            for (int i=0; i<2; ++i) begin
              trn_res[i*128+:128] = {trn_op1_4d[2*i+1],trn_op0_4d[2*i+1]};
            end
          end

          trn2_2q: begin
            for (int i=0; i<1; ++i) begin
              trn_res[i*256+:256] = {trn_op1_2q[2*i+1],trn_op0_2q[2*i+1]};
            end
          end

          default: begin
            for (int i=0; i<8; ++i) begin
              trn_res[i*32+:32] = {trn_op1_16h[2*i],trn_op0_16h[2*i]};
            end
          end
        endcase
      end
    end
  endgenerate

  //////////////////
  // Adders X & Y //
  //////////////////

  // The LSB of the adder results are unused.
  logic unused_adder_x_res_lsb, unused_adder_y_res_lsb;

  // Shared adder control signals
  logic            adder_x_carry_in;
  logic            adder_x_op_b_invert;
  logic            adder_y_carry_in;
  logic            adder_y_op_b_invert;
  logic [WLEN-1:0] adder_y_op_a_blanked;
  logic [WLEN-1:0] adder_y_op_shifter_res_blanked;

  logic [WLEN-1:0] shift_mod_mux_out;
  logic [WLEN-1:0] x_res_operand_a_mux_out;

  generate
    if (AccPQCEn) begin : gen_adder_pqc
      // ADDER X logic
      logic [WLEN-1:0] adder_x_op_a_blanked, adder_x_op_b, adder_x_op_b_blanked;
      logic [WLEN-1:0] adder_x_res;
      logic [15:0]     adder_x_carry_out;

      // ADDER Y logic
      logic [WLEN-1:0]  adder_y_op_a, adder_y_op_b;

      vec_type_e mode;
      assign mode = operation_i.vector_sel ?
                    (operation_i.vector_type[0] == 1'b0 ? VecType_s32 : VecType_h16) :
                    VecType_v256;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN)) u_adder_x_op_a_blanked (
        .in_i (operation_i.operand_a),
        .en_i (alu_predec_bignum_i.adder_x_en),
        .out_o(adder_x_op_a_blanked)
      );

      assign adder_x_op_b = adder_x_op_b_invert ? ~operation_i.operand_b : operation_i.operand_b;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN)) u_adder_x_op_b_blanked (
        .in_i (adder_x_op_b),
        .en_i (alu_predec_bignum_i.adder_x_en),
        .out_o(adder_x_op_b_blanked)
      );

      buffer_bit adder_x (
        .A        (adder_x_op_a_blanked),
        .B        (adder_x_op_b_blanked),
        .word_mode(mode),
        .cin      (adder_x_carry_in),
        .res      (adder_x_res),
        .cout     (adder_x_carry_out)
      );

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN)) u_adder_y_op_a_blanked (
        .in_i (operation_i.operand_a),
        .en_i (alu_predec_bignum_i.adder_y_op_a_en),
        .out_o(adder_y_op_a_blanked)
      );

      assign x_res_operand_a_mux_out =
          alu_predec_bignum_i.x_res_operand_a_sel ? adder_x_res : adder_y_op_a_blanked;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN)) u_adder_y_op_shifter_blanked (
        .in_i (shifter_res),
        .en_i (alu_predec_bignum_i.adder_y_op_shifter_en),
        .out_o(adder_y_op_shifter_res_blanked)
      );

      assign shift_mod_mux_out =
          alu_predec_bignum_i.shift_mod_sel ? adder_y_op_shifter_res_blanked :
          (mode == VecType_h16) ? {16 {ispr_mod_no_intg_i[15:0]}} :
          (mode == VecType_s32) ? { 8 {ispr_mod_no_intg_i[31:0]}} :
          ispr_mod_no_intg_i;

      assign adder_y_op_a = x_res_operand_a_mux_out;
      assign adder_y_op_b = adder_y_op_b_invert ? ~shift_mod_mux_out : shift_mod_mux_out;

      buffer_bit adder_y (
        .A        (adder_y_op_a),
        .B        (adder_y_op_b),
        .word_mode(mode),
        .cin      (adder_y_carry_in),
        .res      (adder_y_res),
        .cout     (gen_adder_y_res_pqc.adder_y_carry_out)
      );

      assign unused_adder_x_res_lsb = adder_x_res[0];
      assign unused_adder_y_res_lsb = adder_y_res[0];

    end else begin : gen_adder
      logic [WLEN:0]   adder_x_op_a_blanked, adder_x_op_b, adder_x_op_b_blanked;
      logic [WLEN+1:0] adder_x_res;

      logic [WLEN:0]   adder_y_op_a, adder_y_op_b;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN+1)) u_adder_x_op_a_blanked (
        .in_i ({operation_i.operand_a, 1'b1}),
        .en_i (alu_predec_bignum_i.adder_x_en),
        .out_o(adder_x_op_a_blanked)
      );

      assign adder_x_op_b = {adder_x_op_b_invert ? ~operation_i.operand_b : operation_i.operand_b,
                            adder_x_carry_in};

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN+1)) u_adder_x_op_b_blanked (
        .in_i (adder_x_op_b),
        .en_i (alu_predec_bignum_i.adder_x_en),
        .out_o(adder_x_op_b_blanked)
      );

      assign adder_x_res = adder_x_op_a_blanked + adder_x_op_b_blanked;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN)) u_adder_y_op_a_blanked (
        .in_i (operation_i.operand_a),
        .en_i (alu_predec_bignum_i.adder_y_op_a_en),
        .out_o(adder_y_op_a_blanked)
      );

      assign x_res_operand_a_mux_out =
          alu_predec_bignum_i.x_res_operand_a_sel ? adder_x_res[WLEN:1] : adder_y_op_a_blanked;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(WLEN)) u_adder_y_op_shifter_blanked (
        .in_i (shifter_res),
        .en_i (alu_predec_bignum_i.adder_y_op_shifter_en),
        .out_o(adder_y_op_shifter_res_blanked)
      );

      assign shift_mod_mux_out =
          alu_predec_bignum_i.shift_mod_sel ? adder_y_op_shifter_res_blanked : ispr_mod_no_intg_i;

      assign adder_y_op_a = {x_res_operand_a_mux_out, 1'b1};
      assign adder_y_op_b = {adder_y_op_b_invert ? ~shift_mod_mux_out : shift_mod_mux_out,
                            adder_y_carry_in};

      assign adder_y_res = adder_y_op_a + adder_y_op_b;

      assign unused_adder_x_res_lsb = adder_x_res[0];
      assign unused_adder_y_res_lsb = adder_y_res[0];
    end
  endgenerate

  //////////////////////////////
  // Shifter & Adders control //
  //////////////////////////////
  logic expected_adder_x_en;
  logic expected_x_res_operand_a_sel;
  logic expected_adder_y_op_a_en;
  logic expected_adder_y_op_shifter_en;
  logic expected_shifter_a_en;
  logic expected_shifter_b_en;
  logic expected_shift_right;
  logic expected_shift_mod_sel;
  logic expected_logic_a_en;
  logic expected_logic_shifter_en;
  logic [3:0] expected_logic_res_sel;

  generate
    if (AccPQCEn) begin : gen_shift_add_ctrl_pqc
      alu_vector_type_t expected_vector_type;
      alu_trn_type_t    expected_trn_type;
      logic             expected_vector_sel;

      always_comb begin
        adder_x_carry_in            = 1'b0;
        adder_x_op_b_invert         = 1'b0;
        adder_y_carry_in            = 1'b0;
        adder_y_op_b_invert         = 1'b0;
        adder_update_flags_en_raw_o = 1'b0;
        logic_update_flags_en_raw_o = 1'b0;

        expected_vector_type            = alu_8s;
        expected_trn_type               = alu_trn_type_t'('0);
        expected_vector_sel             = 1'b0;
        expected_adder_x_en             = 1'b0;
        expected_x_res_operand_a_sel    = 1'b0;
        expected_adder_y_op_a_en        = 1'b0;
        expected_adder_y_op_shifter_en  = 1'b0;
        expected_shifter_a_en           = 1'b0;
        expected_shifter_b_en           = 1'b0;
        expected_shift_right            = 1'b0;
        expected_shift_mod_sel          = 1'b1;
        expected_logic_a_en             = 1'b0;
        expected_logic_shifter_en       = 1'b0;
        expected_logic_res_sel          = '0;

        unique case (operation_i.op)
          AluOpBignumAdd: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A + shifter_res
            // X ignored
            adder_y_carry_in               = 1'b0;
            adder_y_op_b_invert            = 1'b0;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumAddc: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A + shifter_res + flags.C
            // X ignored
            adder_y_carry_in               = selected_flags_i.C;
            adder_y_op_b_invert            = 1'b0;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumAddm: begin
            // X computes A + B
            // Y computes adder_x_res - mod = adder_x_res + ~mod + 1
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether mod subtraction in
            // Y should be applied or not)
            adder_x_carry_in    = 1'b0;
            adder_x_op_b_invert = 1'b0;
            adder_y_carry_in    = 1'b1;
            adder_y_op_b_invert = 1'b1;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
          end
          AluOpBignumAddv: begin
            // X computes A + B
            // Y computes adder_x_res - mod = adder_x_res + ~mod + 1
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether mod subtraction in
            // Y should be applied or not)
            adder_x_carry_in    = 1'b0;
            adder_x_op_b_invert = 1'b0;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
            expected_vector_type         = operation_i.vector_type;
            expected_vector_sel          = operation_i.vector_sel;
          end
          AluOpBignumAddvm: begin
            // X computes A + B
            // Y computes adder_x_res - mod = adder_x_res + ~mod + 1
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether mod subtraction in
            // Y should be applied or not)
            adder_x_carry_in    = 1'b0;
            adder_x_op_b_invert = 1'b0;
            adder_y_carry_in    = 1'b1;
            adder_y_op_b_invert = 1'b1;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
            expected_vector_type         = operation_i.vector_type;
            expected_vector_sel          = operation_i.vector_sel;
          end
          AluOpBignumSub: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A - shifter_res = A + ~shifter_res + 1
            // X ignored
            adder_y_carry_in               = 1'b1;
            adder_y_op_b_invert            = 1'b1;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumSubb: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A - shifter_res + ~flags.C = A + ~shifter_res + flags.C
            // X ignored
            adder_y_carry_in               = ~selected_flags_i.C;
            adder_y_op_b_invert            = 1'b1;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumSubm: begin
            // X computes A - B = A + ~B + 1
            // Y computes adder_x_res + mod
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether subtraction in Y should
            // be applied or not)
            adder_x_carry_in    = 1'b1;
            adder_x_op_b_invert = 1'b1;
            adder_y_carry_in    = 1'b0;
            adder_y_op_b_invert = 1'b0;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
          end
          AluOpBignumSubv: begin
            // X computes A - B = A + ~B + 1
            // Y computes adder_x_res + mod
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether subtraction in Y should
            // be applied or not)
            adder_x_carry_in    = 1'b1;
            adder_x_op_b_invert = 1'b1;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
            expected_vector_type         = operation_i.vector_type;
            expected_vector_sel          = operation_i.vector_sel;
          end
          AluOpBignumSubvm: begin
            // X computes A - B = A + ~B + 1
            // Y computes adder_x_res + mod
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether subtraction in Y should
            // be applied or not)
            adder_x_carry_in    = 1'b1;
            adder_x_op_b_invert = 1'b1;
            adder_y_carry_in    = 1'b0;
            adder_y_op_b_invert = 1'b0;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
            expected_vector_type         = operation_i.vector_type;
            expected_vector_sel          = operation_i.vector_sel;
          end
          AluOpBignumRshi: begin
            // Shifter computes {A, B} >> shift_amt
            // X, Y ignored
            // Feed blanked shifter output (adder_y_op_shifter_res_blanked) to Y to avoid undesired
            // leakage in the zero flag computation.

            expected_shifter_a_en = 1'b1;
            expected_shifter_b_en = 1'b1;
            expected_shift_right  = 1'b1;
          end
          AluOpBignumXor,
          AluOpBignumOr,
          AluOpBignumAnd,
          AluOpBignumNot: begin
            // Shift computes one operand for the logical operation
            // X & Y ignored
            // Feed blanked shifter output (adder_y_op_shifter_res_blanked) to Y to avoid undesired
            // leakage in the zero flag computation.
            logic_update_flags_en_raw_o           = 1'b1;

            expected_shifter_b_en                 = 1'b1;
            expected_shift_right                  = operation_i.shift_right;
            expected_logic_a_en                   = operation_i.op != AluOpBignumNot;
            expected_logic_shifter_en             = 1'b1;
            expected_logic_res_sel[AluOpLogicXor] = operation_i.op == AluOpBignumXor;
            expected_logic_res_sel[AluOpLogicOr]  = operation_i.op == AluOpBignumOr;
            expected_logic_res_sel[AluOpLogicAnd] = operation_i.op == AluOpBignumAnd;
            expected_logic_res_sel[AluOpLogicNot] = operation_i.op == AluOpBignumNot;
          end
          AluOpBignumShv: begin
            expected_vector_type            = operation_i.vector_type;
            expected_vector_sel             = operation_i.vector_sel;
            expected_shifter_b_en           = 1'b1;
            expected_shift_right            = operation_i.shift_right;
            expected_logic_shifter_en       = 1'b1;
            expected_logic_res_sel          = '0;
          end
          AluOpBignumTrn: begin
            expected_trn_type = operation_i.trn_type;
          end
          // No operation, do nothing.
          AluOpBignumNone: ;
          default: ;
        endcase
      end
    end else begin : gen_shift_add_ctrl
      always_comb begin
        adder_x_carry_in            = 1'b0;
        adder_x_op_b_invert         = 1'b0;
        adder_y_carry_in            = 1'b0;
        adder_y_op_b_invert         = 1'b0;
        adder_update_flags_en_raw_o = 1'b0;
        logic_update_flags_en_raw_o = 1'b0;

        expected_adder_x_en             = 1'b0;
        expected_x_res_operand_a_sel    = 1'b0;
        expected_adder_y_op_a_en        = 1'b0;
        expected_adder_y_op_shifter_en  = 1'b0;
        expected_shifter_a_en           = 1'b0;
        expected_shifter_b_en           = 1'b0;
        expected_shift_right            = 1'b0;
        expected_shift_mod_sel          = 1'b1;
        expected_logic_a_en             = 1'b0;
        expected_logic_shifter_en       = 1'b0;
        expected_logic_res_sel          = '0;

        unique case (operation_i.op)
          AluOpBignumAdd: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A + shifter_res
            // X ignored
            adder_y_carry_in               = 1'b0;
            adder_y_op_b_invert            = 1'b0;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumAddc: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A + shifter_res + flags.C
            // X ignored
            adder_y_carry_in               = selected_flags_i.C;
            adder_y_op_b_invert            = 1'b0;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumAddm: begin
            // X computes A + B
            // Y computes adder_x_res - mod = adder_x_res + ~mod + 1
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether mod subtraction in
            // Y should be applied or not)
            adder_x_carry_in    = 1'b0;
            adder_x_op_b_invert = 1'b0;
            adder_y_carry_in    = 1'b1;
            adder_y_op_b_invert = 1'b1;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
          end
          AluOpBignumSub: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A - shifter_res = A + ~shifter_res + 1
            // X ignored
            adder_y_carry_in               = 1'b1;
            adder_y_op_b_invert            = 1'b1;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumSubb: begin
            // Shifter computes B [>>|<<] shift_amt
            // Y computes A - shifter_res + ~flags.C = A + ~shifter_res + flags.C
            // X ignored
            adder_y_carry_in               = ~selected_flags_i.C;
            adder_y_op_b_invert            = 1'b1;
            adder_update_flags_en_raw_o    = 1'b1;
            expected_adder_y_op_shifter_en = 1'b1;

            expected_adder_y_op_a_en = 1'b1;
            expected_shifter_b_en    = 1'b1;
            expected_shift_right     = operation_i.shift_right;
          end
          AluOpBignumSubm: begin
            // X computes A - B = A + ~B + 1
            // Y computes adder_x_res + mod
            // Shifter ignored
            // Output mux chooses result based on top bit of X result (whether subtraction in Y should
            // be applied or not)
            adder_x_carry_in    = 1'b1;
            adder_x_op_b_invert = 1'b1;
            adder_y_carry_in    = 1'b0;
            adder_y_op_b_invert = 1'b0;

            expected_adder_x_en          = 1'b1;
            expected_x_res_operand_a_sel = 1'b1;
            expected_shift_mod_sel       = 1'b0;
          end
          AluOpBignumRshi: begin
            // Shifter computes {A, B} >> shift_amt
            // X, Y ignored
            // Feed blanked shifter output (adder_y_op_shifter_res_blanked) to Y to avoid undesired
            // leakage in the zero flag computation.

            expected_shifter_a_en = 1'b1;
            expected_shifter_b_en = 1'b1;
            expected_shift_right  = 1'b1;
          end
          AluOpBignumXor,
          AluOpBignumOr,
          AluOpBignumAnd,
          AluOpBignumNot: begin
            // Shift computes one operand for the logical operation
            // X & Y ignored
            // Feed blanked shifter output (adder_y_op_shifter_res_blanked) to Y to avoid undesired
            // leakage in the zero flag computation.
            logic_update_flags_en_raw_o           = 1'b1;

            expected_shifter_b_en                 = 1'b1;
            expected_shift_right                  = operation_i.shift_right;
            expected_logic_a_en                   = operation_i.op != AluOpBignumNot;
            expected_logic_shifter_en             = 1'b1;
            expected_logic_res_sel[AluOpLogicXor] = operation_i.op == AluOpBignumXor;
            expected_logic_res_sel[AluOpLogicOr]  = operation_i.op == AluOpBignumOr;
            expected_logic_res_sel[AluOpLogicAnd] = operation_i.op == AluOpBignumAnd;
            expected_logic_res_sel[AluOpLogicNot] = operation_i.op == AluOpBignumNot;
          end
          // No operation, do nothing.
          AluOpBignumNone: ;
          default: ;
        endcase
      end
    end
  endgenerate

  logic [$clog2(WLEN)-1:0] expected_shift_amt;
  assign expected_shift_amt = operation_i.shift_amt;

  // SEC_CM: CTRL.REDUN
  generate
    if (AccPQCEn) begin : gen_alu_predec_error_pqc
      assign alu_predec_error_o =
        |{expected_adder_x_en != alu_predec_bignum_i.adder_x_en,
          expected_x_res_operand_a_sel != alu_predec_bignum_i.x_res_operand_a_sel,
          expected_adder_y_op_a_en != alu_predec_bignum_i.adder_y_op_a_en,
          expected_adder_y_op_shifter_en != alu_predec_bignum_i.adder_y_op_shifter_en,
          expected_shifter_a_en != alu_predec_bignum_i.shifter_a_en,
          expected_shifter_b_en != alu_predec_bignum_i.shifter_b_en,
          expected_shift_right != alu_predec_bignum_i.shift_right,
          gen_shift_add_ctrl_pqc.expected_vector_type != alu_predec_bignum_i.vector_type,
          gen_shift_add_ctrl_pqc.expected_trn_type != alu_predec_bignum_i.trn_type,
          gen_shift_add_ctrl_pqc.expected_vector_sel != alu_predec_bignum_i.vector_sel,
          expected_shift_amt != alu_predec_bignum_i.shift_amt,
          expected_shift_mod_sel != alu_predec_bignum_i.shift_mod_sel,
          expected_logic_a_en != alu_predec_bignum_i.logic_a_en,
          expected_logic_shifter_en != alu_predec_bignum_i.logic_shifter_en,
          expected_logic_res_sel != alu_predec_bignum_i.logic_res_sel};
    end else begin : gen_alu_predec_error
      assign alu_predec_error_o =
        |{expected_adder_x_en != alu_predec_bignum_i.adder_x_en,
          expected_x_res_operand_a_sel != alu_predec_bignum_i.x_res_operand_a_sel,
          expected_adder_y_op_a_en != alu_predec_bignum_i.adder_y_op_a_en,
          expected_adder_y_op_shifter_en != alu_predec_bignum_i.adder_y_op_shifter_en,
          expected_shifter_a_en != alu_predec_bignum_i.shifter_a_en,
          expected_shifter_b_en != alu_predec_bignum_i.shifter_b_en,
          expected_shift_right != alu_predec_bignum_i.shift_right,
          expected_shift_amt != alu_predec_bignum_i.shift_amt,
          expected_shift_mod_sel != alu_predec_bignum_i.shift_mod_sel,
          expected_logic_a_en != alu_predec_bignum_i.logic_a_en,
          expected_logic_shifter_en != alu_predec_bignum_i.logic_shifter_en,
          expected_logic_res_sel != alu_predec_bignum_i.logic_res_sel};
    end
  endgenerate

  ////////////////////////
  // Logical operations //
  ////////////////////////

  logic [WLEN-1:0] logical_res_mux_in [4];
  logic [WLEN-1:0] logical_op_a_blanked;
  logic [WLEN-1:0] logical_op_shifter_res_blanked;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_logical_op_a_blanker (
    .in_i (operation_i.operand_a),
    .en_i (alu_predec_bignum_i.logic_a_en),
    .out_o(logical_op_a_blanked)
  );

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(WLEN)) u_logical_op_shifter_res_blanker (
    .in_i (shifter_res),
    .en_i (alu_predec_bignum_i.logic_shifter_en),
    .out_o(logical_op_shifter_res_blanked)
  );

  assign logical_res_mux_in[AluOpLogicXor] = logical_op_a_blanked ^ logical_op_shifter_res_blanked;
  assign logical_res_mux_in[AluOpLogicOr]  = logical_op_a_blanked | logical_op_shifter_res_blanked;
  assign logical_res_mux_in[AluOpLogicAnd] = logical_op_a_blanked & logical_op_shifter_res_blanked;
  assign logical_res_mux_in[AluOpLogicNot] = ~logical_op_shifter_res_blanked;

  // SEC_CM: DATA_REG_SW.SCA
  prim_onehot_mux #(
    .Width (WLEN),
    .Inputs(4)
  ) u_logical_res_mux (
    .clk_i,
    .rst_ni,
    .in_i  (logical_res_mux_in),
    .sel_i (alu_predec_bignum_i.logic_res_sel),
    .out_o (logical_res)
  );

  ////////////////////////
  // Output multiplexer //
  ////////////////////////

  logic adder_y_res_used;

  generate
    if (AccPQCEn) begin : gen_output_mux_pqc
      always_comb begin
        operation_result_o = adder_y_res;
        adder_y_res_used = 1'b1;
        unique case (operation_i.op)
          AluOpBignumAdd,
          AluOpBignumAddc,
          AluOpBignumSub,
          AluOpBignumSubb: begin
            operation_result_o = adder_y_res;
            adder_y_res_used = 1'b1;
          end

          // For pseudo-mod operations the result depends upon initial a + b / a - b result that is
          // computed in X. Operation to add/subtract mod (X + mod / X - mod) is computed in Y.
          // Subtraction is computed using in the X & Y adders as a - b == a + ~b + 1. Note that
          // for a - b the top bit of the result will be set if a - b >= 0 and otherwise clear.

          // BN.ADDM - X = a + b, Y = X - mod, subtract mod if a + b >= mod
          // * If X generates carry a + b > mod (as mod is 256-bit) - Select Y result
          // * If Y generates carry X - mod == (a + b) - mod >= 0 hence a + b >= mod, note this is
          // only valid if X does not generate carry - Select Y result
          // * If neither happen a + b < mod - Select X result
          AluOpBignumAddm: begin
            // `adder_y_res` is always used: either as condition in the following `if` statement
            // or, if the `if` statement short-circuits, in the body of the `if` statement.
            adder_y_res_used = 1'b1;
            if (gen_adder_pqc.adder_x_carry_out[15] || gen_adder_y_res_pqc.adder_y_carry_out[15])
            begin
              operation_result_o = adder_y_res;
            end else begin
              operation_result_o = gen_adder_pqc.adder_x_res;
            end
          end

          AluOpBignumAddv: begin
            operation_result_o = gen_adder_pqc.adder_x_res;
          end

          AluOpBignumAddvm: begin
            // `adder_y_res` is always used: either as condition in the following `if` statement
            // or, if the `if` statement short-circuits, in the body of the `if` statement.
            adder_y_res_used = 1'b1;

            for (int i = 0; i < 16; i += 2) begin
              operation_result_o[i*16 +: 16] = ((operation_i.vector_type[0]) ?
                (gen_adder_pqc.adder_x_carry_out[i] || gen_adder_y_res_pqc.adder_y_carry_out[i]) :
                (gen_adder_pqc.adder_x_carry_out[i + 1]
                || gen_adder_y_res_pqc.adder_y_carry_out[i + 1])) ?
                adder_y_res[i*16 +: 16] : gen_adder_pqc.adder_x_res[i*16 +: 16];
              operation_result_o[(i + 1)* 16 +: 16] =
                (gen_adder_pqc.adder_x_carry_out[i + 1]
                || gen_adder_y_res_pqc.adder_y_carry_out[i + 1]) ?
                adder_y_res[(i + 1)*16 +: 16] : gen_adder_pqc.adder_x_res[(i + 1)*16 +: 16];
            end
          end

          // BN.SUBM - X = a - b, Y = X + mod, add mod if a - b < 0
          // * If X generates carry a - b >= 0 - Select X result
          // * Otherwise select Y result
          AluOpBignumSubm: begin
            if (gen_adder_pqc.adder_x_carry_out[15]) begin
              operation_result_o = gen_adder_pqc.adder_x_res;
              adder_y_res_used = 1'b0;
            end else begin
              operation_result_o = adder_y_res;
              adder_y_res_used = 1'b1;
            end
          end

          AluOpBignumSubv: begin
            operation_result_o = gen_adder_pqc.adder_x_res;
          end
          AluOpBignumSubvm: begin
            adder_y_res_used = 1'b1;

            for (int i = 0; i < 16; i += 2) begin
              operation_result_o[i*16 +: 16] = ((operation_i.vector_type[0]) ?
                  gen_adder_pqc.adder_x_carry_out[i] : gen_adder_pqc.adder_x_carry_out[i + 1]) ?
                      gen_adder_pqc.adder_x_res[i*16 +: 16] : adder_y_res[i*16 +: 16];
              operation_result_o[(i + 1)* 16 +: 16] = gen_adder_pqc.adder_x_carry_out[i + 1] ?
                    gen_adder_pqc.adder_x_res[(i + 1)*16 +: 16] : adder_y_res[(i + 1)*16 +: 16];
            end
          end

          AluOpBignumRshi,AluOpBignumShv: begin
            operation_result_o = shifter_res[WLEN-1:0];
            adder_y_res_used = 1'b0;
          end

          AluOpBignumTrn: begin
            operation_result_o = gen_trn_pqc.trn_res;
            adder_y_res_used = 1'b0;
          end

          AluOpBignumXor,
          AluOpBignumOr,
          AluOpBignumAnd,
          AluOpBignumNot: begin
            operation_result_o = logical_res;
            adder_y_res_used = 1'b0;
          end
          default: ;
        endcase
      end
    end else begin : gen_output_mux
      always_comb begin
        operation_result_o = adder_y_res[WLEN:1];
        adder_y_res_used = 1'b1;
        unique case (operation_i.op)
          AluOpBignumAdd,
          AluOpBignumAddc,
          AluOpBignumSub,
          AluOpBignumSubb: begin
            operation_result_o = adder_y_res[WLEN:1];
            adder_y_res_used = 1'b1;
          end

          // For pseudo-mod operations the result depends upon initial a + b / a - b result that is
          // computed in X. Operation to add/subtract mod (X + mod / X - mod) is computed in Y.
          // Subtraction is computed using in the X & Y adders as a - b == a + ~b + 1. Note that
          // for a - b the top bit of the result will be set if a - b >= 0 and otherwise clear.

          // BN.ADDM - X = a + b, Y = X - mod, subtract mod if a + b >= mod
          // * If X generates carry a + b > mod (as mod is 256-bit) - Select Y result
          // * If Y generates carry X - mod == (a + b) - mod >= 0 hence a + b >= mod, note this is
          // only valid if X does not generate carry - Select Y result
          // * If neither happen a + b < mod - Select X result
          AluOpBignumAddm: begin
            // `adder_y_res` is always used: either as condition in the following `if` statement
            // or, if the `if` statement short-circuits, in the body of the `if` statement.
            adder_y_res_used = 1'b1;
            if (gen_adder.adder_x_res[WLEN+1] || adder_y_res[WLEN+1]) begin
              operation_result_o = adder_y_res[WLEN:1];
            end else begin
              operation_result_o = gen_adder.adder_x_res[WLEN:1];
            end
          end

          // BN.SUBM - X = a - b, Y = X + mod, add mod if a - b < 0
          // * If X generates carry a - b >= 0 - Select X result
          // * Otherwise select Y result
          AluOpBignumSubm: begin
            if (gen_adder.adder_x_res[WLEN+1]) begin
              operation_result_o = gen_adder.adder_x_res[WLEN:1];
              adder_y_res_used = 1'b0;
            end else begin
              operation_result_o = adder_y_res[WLEN:1];
              adder_y_res_used = 1'b1;
            end
          end

          AluOpBignumRshi: begin
            operation_result_o = shifter_res[WLEN-1:0];
            adder_y_res_used = 1'b0;
          end

          AluOpBignumXor,
          AluOpBignumOr,
          AluOpBignumAnd,
          AluOpBignumNot: begin
            operation_result_o = logical_res;
            adder_y_res_used = 1'b0;
          end
          default: ;
        endcase
      end
    end
  endgenerate

  // Tie off unused signals.
  logic unused_operation_commit;
  assign unused_operation_commit = operation_commit_i;

  // Determine if `mod_intg_q` is used.  The control signals are only valid if `operation_i.op` is
  // not none. If `shift_mod_sel` is low, `mod_intg_q` flows into `adder_y_op_b` and from there
  // into `adder_y_res`.  In this case, `mod_intg_q` is used iff  `adder_y_res` flows into
  // `operation_result_o`.
  assign mod_used_o = operation_valid_i & (operation_i.op != AluOpBignumNone)
                    & !alu_predec_bignum_i.shift_mod_sel & adder_y_res_used;

  `ASSERT_KNOWN(ModUsed_A, mod_used_o)

  // Blanking Assertions
  // All blanking assertions are reset with predec_error or overall error in the whole system
  // -indicated by operation_commit_i port- as ACC does not guarantee blanking in the case
  // of an error.

  // adder_x_res related blanking
  generate
    if (AccPQCEn) begin : gen_blanking_x_res_pqc
      `ASSERT(BlankingBignumAluXOp_A,
              !expected_adder_x_en |->
              {gen_adder_pqc.adder_x_op_a_blanked, gen_adder_pqc.adder_x_op_b_blanked,
               gen_adder_pqc.adder_x_res} == '0,
              clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)
    end else begin : gen_blanking_x_res
      `ASSERT(BlankingBignumAluXOp_A,
              !expected_adder_x_en |->
              {gen_adder.adder_x_op_a_blanked, gen_adder.adder_x_op_b_blanked,
               gen_adder.adder_x_res} == '0,
              clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)
    end
  endgenerate

  // adder_y_res related blanking
  `ASSERT(BlankingBignumAluYOpA_A,
          !expected_adder_y_op_a_en |-> adder_y_op_a_blanked == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)
  `ASSERT(BlankingBignumAluYOpShft_A,
          !expected_adder_y_op_shifter_en |-> adder_y_op_shifter_res_blanked == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)

  // Adder Y must be blanked when its result is not used, with one exception: For `BN.SUBM` with
  // `a >= b` (thus the result of Adder X has the carry bit set), the result of Adder Y is not used
  // but it cannot be blanked solely based on the carry bit.
  generate
    if (AccPQCEn) begin : gen_blanking_alu_y_res_pqc
      `ASSERT(BlankingBignumAluYResUsed_A,
              !adder_y_res_used
              && !(operation_i.op == AluOpBignumSubm && gen_adder_pqc.adder_x_res[WLEN+1])
              |-> {x_res_operand_a_mux_out, gen_adder_pqc.adder_y_op_b} == '0,
              clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)
    end else begin : gen_blanking_alu_y_res
      `ASSERT(BlankingBignumAluYResUsed_A,
              !adder_y_res_used
              && !(operation_i.op == AluOpBignumSubm && gen_adder.adder_x_res[WLEN+1])
              |-> {x_res_operand_a_mux_out, gen_adder.adder_y_op_b} == '0,
              clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)
    end
  endgenerate

  // shifter_res related blanking
  `ASSERT(BlankingBignumAluShftA_A,
          !expected_shifter_a_en |-> shifter_operand_a_blanked == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)

  `ASSERT(BlankingBignumAluShftB_A,
          !expected_shifter_b_en |-> shifter_operand_b_blanked == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)

  `ASSERT(BlankingBignumAluShftRes_A,
          !(expected_shifter_a_en || expected_shifter_b_en) |-> shifter_res == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)

  // logical_res related blanking
  `ASSERT(BlankingBignumAluLogicOpA_A,
          !expected_logic_a_en |-> logical_op_a_blanked == '0,
          clk_i, !rst_ni || alu_predec_error_o  || !operation_commit_i)

  `ASSERT(BlankingBignumAluLogicShft_A,
          !expected_logic_shifter_en |-> logical_op_shifter_res_blanked == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)

  `ASSERT(BlankingBignumAluLogicRes_A,
          !(expected_logic_a_en || expected_logic_shifter_en) |-> logical_res == '0,
          clk_i, !rst_ni || alu_predec_error_o || !operation_commit_i)

endmodule
