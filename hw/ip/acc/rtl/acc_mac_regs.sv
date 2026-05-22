// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

// TODO: This module needs to have the remaining ISPR/WSR registers ported to it.
// For now it only has the ACC and ACCH registers from the Bignum MAC, but the
// actual WSRs are still in the bignum ALU.

module acc_mac_regs
  import acc_pkg::*;
#(
  // Enabling PQC hardware support with vector ISA extension
  parameter bit AccPQCEn = 1'b1,
  localparam int ADDER_WIDTH = (AccPQCEn) ? 2*WLEN : WLEN
)(
  input logic clk_i,
  input logic rst_ni,

  input mac_bignum_operation_t  operation_i,
  input logic                   mac_en_i,
  input logic                   mac_commit_i,
  input logic [ADDER_WIDTH-1:0] mac_adder_result_i,

  input  mac_predec_bignum_t mac_predec_bignum_i,
  output logic               operation_intg_violation_err_o,

  input  logic [WLEN-1:0] urnd_data_i,
  input  logic            sec_wipe_acc_urnd_i,
  input  logic            sec_wipe_acch_urnd_i,
  input  logic            sec_wipe_running_i,
  output logic            sec_wipe_err_o,

  output logic [ExtWLEN-1:0] ispr_acch_intg_o,
  output logic [WLEN-1:0]    acch_blanked_o,
  input  logic [ExtWLEN-1:0] ispr_acch_wr_data_intg_i,
  input  logic               ispr_acch_wr_en_i,

  output logic [ExtWLEN-1:0] ispr_acc_intg_o,
  output logic [WLEN-1:0]    acc_blanked_o,
  input  logic [ExtWLEN-1:0] ispr_acc_wr_data_intg_i,
  input  logic               ispr_acc_wr_en_i
);
  // The MAC operates on quarter-words, QWLEN gives the number of bits in a quarter-word.
  localparam int unsigned QWLEN = WLEN / 4;

  // ACC
  // ECC encode and decode of accumulator register
  logic [ExtWLEN-1:0]             acc_intg_d;
  logic [ExtWLEN-1:0]             acc_intg_q;
  logic [WLEN-1:0]                acc_no_intg_d;
  logic [WLEN-1:0]                acc_no_intg_q;
  logic [ExtWLEN-1:0]             acc_intg_calc;
  logic [2*BaseWordsPerWLEN-1:0]  acc_intg_err;
  logic                           acc_en;

  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_acc_words
    prim_secded_inv_39_32_enc i_secded_enc (
      .data_i (acc_no_intg_d[i_word*32+:32]),
      .data_o (acc_intg_calc[i_word*39+:39])
    );
    prim_secded_inv_39_32_dec i_secded_dec (
      .data_i     (acc_intg_q[i_word*39+:39]),
      .data_o     (/* unused because we abort on any integrity error */),
      .syndrome_o (/* unused */),
      .err_o      (acc_intg_err[i_word*2+:2])
    );
    assign acc_no_intg_q[i_word*32+:32] = acc_intg_q[i_word*39+:32];
  end

  always_comb begin
    acc_no_intg_d = '0;
    unique case (1'b1)
      // Non-encoded inputs have to be encoded before writing to the register.
      sec_wipe_acc_urnd_i: begin
        acc_no_intg_d = urnd_data_i;
        acc_intg_d = acc_intg_calc;
      end
      default: begin
        // If performing an ACC ISPR write the next accumulator value is taken from the ISPR write
        // data, otherwise it is drawn from the adder result. The new accumulator can be optionally
        // shifted right by one half-word (shift_acc).
        if (ispr_acc_wr_en_i) begin
          acc_intg_d = ispr_acc_wr_data_intg_i;
        end else begin
          acc_no_intg_d = operation_i.shift_acc ?
              {{QWLEN*2{1'b0}}, mac_adder_result_i[QWLEN*2+:QWLEN*2]} :
              mac_adder_result_i[0+:WLEN];
          acc_intg_d = acc_intg_calc;
        end
      end
    endcase
  end

  // Only write to accumulator if the MAC is enabled or an ACC ISPR write is occurring or secure
  // wipe of the internal state is occurring.
  assign acc_en = (mac_en_i & mac_commit_i) | ispr_acc_wr_en_i | sec_wipe_acc_urnd_i;

  always_ff @(posedge clk_i) begin
    if (acc_en) begin
      acc_intg_q <= acc_intg_d;
    end
  end

  // SEC_CM: DATA_REG_SW.SCA
  // acc_rd_en is so if .Z set in MULQACC (zero_acc) so accumulator reads as 0
  prim_blanker #(.Width(WLEN)) u_acc_blanker (
    .in_i (acc_no_intg_q),
    .en_i (mac_predec_bignum_i.acc_rd_en),
    .out_o(acc_blanked_o)
  );

  assign ispr_acc_intg_o = acc_intg_q;

  `ASSERT(NoISPRAccWrAndMacEn, ~(ispr_acc_wr_en_i & mac_en_i))

  // ACCH
  generate
    if (AccPQCEn) begin : gen_acch_reg
      // ECC encode and decode of accumulator high register
      logic [ExtWLEN-1:0]             acch_intg_d;
      logic [ExtWLEN-1:0]             acch_intg_q;
      logic [WLEN-1:0]                acch_no_intg_d;
      logic [WLEN-1:0]                acch_no_intg_q;
      logic [ExtWLEN-1:0]             acch_intg_calc;
      logic [2*BaseWordsPerWLEN-1:0]  acch_intg_err;
      logic                           acch_en;

      for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_acch_words
        prim_secded_inv_39_32_enc i_secdedh_enc (
          .data_i (acch_no_intg_d[i_word*32+:32]),
          .data_o (acch_intg_calc[i_word*39+:39])
        );
        prim_secded_inv_39_32_dec i_secdedh_dec (
          .data_i     (acch_intg_q[i_word*39+:39]),
          .data_o     (/* unused because we abort on any integrity error */),
          .syndrome_o (/* unused */),
          .err_o      (acch_intg_err[i_word*2+:2])
        );
        assign acch_no_intg_q[i_word*32+:32] = acch_intg_q[i_word*39+:32];
      end

      always_comb begin
        acch_no_intg_d = '0;
        unique case (1'b1)
          // Non-encoded inputs have to be encoded before writing to the register.
          sec_wipe_acch_urnd_i: begin
            acch_no_intg_d = urnd_data_i;
            acch_intg_d = acch_intg_calc;
          end
          default: begin
            if (ispr_acch_wr_en_i) begin
              acch_intg_d = ispr_acch_wr_data_intg_i;
            end else begin
              acch_no_intg_d = mac_adder_result_i[WLEN+:WLEN];
              acch_intg_d = acch_intg_calc;
            end
          end
        endcase
      end

      // Only write to accumulator if the MAC is enabled or an ACC ISPR write is occurring or secure
      // wipe of the internal state is occurring.
      assign acch_en = (mac_en_i & mac_commit_i & operation_i.mulv) |
                       ispr_acch_wr_en_i | sec_wipe_acch_urnd_i;

      always_ff @(posedge clk_i) begin
        if (acch_en) begin
          acch_intg_q <= acch_intg_d;
        end
      end

      // SEC_CM: DATA_REG_SW.SCA
      // acc_rd_en is so if .Z set in MULQACC (zero_acc) so accumulator reads as 0
      prim_blanker #(.Width(WLEN)) u_acch_blanker (
        .in_i (acch_no_intg_q),
        .en_i (mac_predec_bignum_i.acc_rd_en & operation_i.mulv),
        .out_o(acch_blanked_o)
      );

      assign ispr_acch_intg_o = acch_intg_q;

      `ASSERT(NoISPRAccHWrAndMacEn, ~(ispr_acch_wr_en_i & mac_en_i))
    end
  endgenerate

  // SHARED
  // Propagate integrity error only if accumulator register is used: `acc_intg_q` flows into
  // `operation_result_o` via `acc`, `adder_op_b`, and `adder_result` iff the MAC is enabled and the
  // current operation does not zero the accumulation register.
  logic acc_used;
  assign acc_used = mac_en_i & ~operation_i.zero_acc;

  generate
    if (AccPQCEn) begin : gen_op_intg_err_pqc
      // If the MAC is enabled then the ACCH integrity error should be propagated directly
      assign operation_intg_violation_err_o = (acc_used & |(acc_intg_err))
                                              | (mac_en_i & |(gen_acch_reg.acch_intg_err));
    end else begin : gen_op_intg_err
      assign operation_intg_violation_err_o = acc_used & |(acc_intg_err);
    end
  endgenerate

  generate
    if (AccPQCEn) begin : gen_sec_wipe_err_pqc
      assign sec_wipe_err_o = (sec_wipe_acc_urnd_i | sec_wipe_acch_urnd_i) & ~sec_wipe_running_i;
    end else begin : gen_sec_wipe_err
      assign sec_wipe_err_o = sec_wipe_acc_urnd_i & ~sec_wipe_running_i;
    end
  endgenerate

endmodule