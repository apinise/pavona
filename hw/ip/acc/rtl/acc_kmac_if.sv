// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

/**
 * ACC <-> KMAC sideload interface and WSRs 
 */

module acc_kmac_if
  import acc_pkg::*;
#(
  localparam int Share    = 2
) (
  input logic clk_i,
  input logic rst_ni,

  // ISPR read/write interface
  input  ispr_predec_bignum_t         ispr_predec_bignum_i,
  input  ispr_e                       ispr_addr_i,
  input  logic [31:0]                 ispr_base_wdata_i,
  input  logic [BaseWordsPerWLEN-1:0] ispr_base_wr_en_i,
  input  logic [ExtWLEN-1:0]          ispr_bignum_wdata_intg_i,
  input  logic                        ispr_bignum_wr_en_i,
  input  logic                        ispr_wr_commit_i,
  input  logic                        ispr_init_i,

  // Predecode errors for blanking control assertions
  input  logic                  ispr_predec_error_i,
  input  logic                  alu_predec_error_i,
  input  alu_bignum_operation_t operation_commit_i,

  // Secure wipe for KMAC WSRs
  input  logic            sec_wipe_kmac_regs_urnd_i,
  input  logic [WLEN-1:0] urnd_data_i,

  // KMAC interface
  output logic kmac_intf_fatal_error_o,
  output logic kmac_intf_recov_error_o,
  output logic kmac_intg_err_o,

  output logic kmac_msg_write_ready_o   [Share],
  output logic kmac_msg_pending_write_o [Share],
  output logic kmac_digest_valid_o,

  // TODO: TMP INTG outputs to be replaced by local mux
  output logic [31:0]             kmac_cfg_intg_o,
  output logic [31:0]             kmac_status_intg_o,
  output logic [ExtWLEN-1:0]      kmac_msg_intg_o    [Share],
  output logic [ExtDigestLen-1:0] kmac_digest_intg_o [Share],

  output kmac_pkg::app_req_t kmac_app_req_o,
  input  kmac_pkg::app_rsp_t kmac_app_rsp_i
);

  // CFG
  logic [BaseIntgWidth-1:0] kmac_cfg_intg_q;
  logic [31:0]              kmac_cfg_no_intg_d;
  logic [BaseIntgWidth-1:0] kmac_cfg_intg_d;
  logic [BaseIntgWidth-1:0] kmac_cfg_intg_calc;
  logic                     kmac_cfg_ispr_wr_en;
  logic                     kmac_cfg_wr_en;
  logic [1:0]               kmac_cfg_intg_err;
  logic                     kmac_new_cfg_q;
  logic                     kmac_cfg_mask_mode;

  logic [ExtWLEN-1:0] ispr_kmac_cfg_bignum_wdata_intg_blanked;

  prim_secded_inv_39_32_enc u_kmac_cfg_secded_enc (
    .data_i (kmac_cfg_no_intg_d),
    .data_o (kmac_cfg_intg_calc)
  );

  prim_secded_inv_39_32_dec u_kmac_cfg_secded_dec (
    .data_i     (kmac_cfg_intg_q),
    .data_o     (/* unused because we abort on any integrity error */),
    .syndrome_o (/* unused */),
    .err_o      (kmac_cfg_intg_err)
  );

  prim_blanker #(.Width(ExtWLEN)) u_ispr_kmac_cfg_bignum_wdata_blanker (
    .in_i (ispr_bignum_wdata_intg_i),
    .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprKmacCfg]),
    .out_o(ispr_kmac_cfg_bignum_wdata_intg_blanked)
  );

  // Index 0 because only first 32-bit word contains cfg
  assign kmac_cfg_ispr_wr_en = (ispr_addr_i == IsprKmacCfg) &
                               (ispr_base_wr_en_i[0] | ispr_bignum_wr_en_i) &
                               ispr_wr_commit_i;

  assign kmac_cfg_wr_en = (ispr_init_i | kmac_cfg_ispr_wr_en) & !kmac_app_rsp_i.error;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_cfg_intg_q <= '0;
    end else if (kmac_cfg_wr_en) begin
      kmac_cfg_intg_q <= kmac_cfg_intg_d;
    end
  end

  always_comb begin
    unique case (1'b1)
      ispr_init_i: begin
        kmac_cfg_no_intg_d  = 32'b0;
        kmac_cfg_intg_d     = kmac_cfg_intg_calc;
      end
      ispr_base_wr_en_i[0]: begin // Index 0 because only first 32-bit word contains cfg
        kmac_cfg_no_intg_d  = ispr_base_wdata_i;
        kmac_cfg_intg_d     = kmac_cfg_intg_calc;
      end
      default: begin
        kmac_cfg_no_intg_d  = 32'b0;
        kmac_cfg_intg_d     = ispr_kmac_cfg_bignum_wdata_intg_blanked[38:0];
      end
    endcase
  end

  `ASSERT(KmacCfgWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[0]}))

  // PARTIAL WRITE
  logic [BaseIntgWidth-1:0] kmac_pw_intg_q;
  logic [31:0]              kmac_pw_no_intg_d;
  logic [BaseIntgWidth-1:0] kmac_pw_intg_d;
  logic [BaseIntgWidth-1:0] kmac_pw_intg_calc;
  logic                     kmac_pw_ispr_wr_en;
  logic                     kmac_pw_wr_en;
  logic [1:0]               kmac_pw_intg_err;
  logic [5:0]               kmac_pw_mask;
  logic                     kmac_pending_writes;
  logic                     kmac_pw_rst;

  // Nets from other blocks needed to reset the partial write
  logic                     kmac_msg_fifo_wvalid [Share];
  logic                     kmac_msg_valid_q     [Share];
  logic                     kmac_sent_last;

  logic [ExtWLEN-1:0] ispr_kmac_pw_bignum_wdata_intg_blanked;

  prim_secded_inv_39_32_enc u_kmac_pw_secded_enc (
    .data_i (kmac_pw_no_intg_d),
    .data_o (kmac_pw_intg_calc)
  );

  prim_secded_inv_39_32_dec u_kmac_pw_secded_dec (
    .data_i     (kmac_pw_intg_q),
    .data_o     (/* unused because we abort on any integrity error */),
    .syndrome_o (/* unused */),
    .err_o      (kmac_pw_intg_err)
  );

  prim_blanker #(.Width(ExtWLEN)) u_ispr_kmac_pw_bignum_wdata_blanker (
    .in_i (ispr_bignum_wdata_intg_i),
    .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprKmacPartialW]),
    .out_o(ispr_kmac_pw_bignum_wdata_intg_blanked)
  );

  // Index 0 because only first 32-bit word contains cfg
  assign kmac_pw_ispr_wr_en = (ispr_addr_i == IsprKmacPartialW) &
                              (ispr_base_wr_en_i[0] | ispr_bignum_wr_en_i) &
                              ispr_wr_commit_i;

  always_comb begin
    if (kmac_cfg_mask_mode) begin
      kmac_pw_wr_en = (ispr_init_i | kmac_pw_ispr_wr_en) &
                      ((~kmac_msg_valid_q[0] & ~kmac_msg_valid_q[1]) | kmac_sent_last);
      kmac_pending_writes = kmac_msg_pending_write_o[0] | kmac_msg_pending_write_o[1];
    end else begin
      kmac_pw_wr_en = (ispr_init_i | kmac_pw_ispr_wr_en) &
                      (~kmac_msg_valid_q[0] | kmac_sent_last);
      kmac_pending_writes = kmac_msg_pending_write_o[0];
    end
  end

  always_ff @(posedge clk_i) begin
    if (kmac_pw_wr_en | kmac_new_cfg_q | kmac_pw_rst) begin
      kmac_pw_intg_q  <= kmac_pw_intg_d;
    end
  end

  // Make an FSM to control partial word reset. Need to have written to both share WSR
  // This waits until the pending write has been written into the packer to reset the partial word
  kmac_write_state_e write_state_d, write_state_q;

  always_comb begin
    // Default assignments
    write_state_d = write_state_q;
    kmac_pw_rst   = 1'b0;

    unique case (write_state_q)
      StMsgWait: begin
        if (kmac_msg_fifo_wvalid[0]) begin
          if (kmac_cfg_mask_mode) begin
            write_state_d = StMsgShare0;
          end else begin
            kmac_pw_rst   = 1'b1;
          end
        end else if (kmac_msg_fifo_wvalid[1]) begin
          write_state_d = StMsgShare1;
        end
      end
      StMsgShare0: begin
        if (kmac_msg_fifo_wvalid[1]) begin
          write_state_d = StMsgWait;
          kmac_pw_rst   = 1'b1;
        end
      end
      StMsgShare1: begin
        if (kmac_msg_fifo_wvalid[0]) begin
          write_state_d = StMsgWait;
          kmac_pw_rst   = 1'b1;
        end
      end
      default: ; // Consider triggering an error or alert in this case.
    endcase
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      write_state_q <= StMsgWait;
    end else begin
      write_state_q <= write_state_d;
    end
  end

  always_comb begin
    unique case(1'b1)
      ispr_init_i: begin
        kmac_pw_no_intg_d = 32'b0;
        kmac_pw_intg_d    = kmac_pw_intg_calc;
      end
      ispr_base_wr_en_i[0] & !kmac_pending_writes: begin
        kmac_pw_no_intg_d = ispr_base_wdata_i;
        kmac_pw_intg_d    = kmac_pw_intg_calc;
      end
      kmac_new_cfg_q: begin
        kmac_pw_no_intg_d = 32'h20; // Set to full length at the start of cfg
        kmac_pw_intg_d    = kmac_pw_intg_calc;
      end
      kmac_pw_rst: begin // Reset the partial word at each write
        kmac_pw_no_intg_d = 32'h20;
        kmac_pw_intg_d    = kmac_pw_intg_calc;
      end
      default: begin
        kmac_pw_no_intg_d = 32'b0;
        kmac_pw_intg_d    = ispr_kmac_pw_bignum_wdata_intg_blanked[38:0];
      end
    endcase
  end

  assign kmac_pw_mask = kmac_pw_intg_q[5:0];

  `ASSERT(KmacPWWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[0]}))

  // MSG SHARE Nets
  logic [ExtWLEN-1:0]             kmac_msg_intg_q       [Share];
  logic [ExtWLEN-1:0]             kmac_msg_intg_d       [Share];
  logic [BaseWordsPerWLEN-1:0]    kmac_msg_ispr_wr_en   [Share];
  logic [BaseWordsPerWLEN-1:0]    kmac_msg_ispr_base_wr [Share];
  logic [BaseWordsPerWLEN-1:0]    kmac_msg_wr_en        [Share];
  logic [WLEN-1:0]                kmac_msg_no_intg_d    [Share];
  logic [WLEN-1:0]                kmac_msg_no_intg_q    [Share];
  logic [ExtWLEN-1:0]             kmac_msg_intg_calc    [Share];
  logic [2*BaseWordsPerWLEN-1:0]  kmac_msg_intg_err     [Share];
  logic                           kmac_msg_wr_stall     [Share];
  logic                           kmac_msg_write        [Share];

  logic [ExtWLEN-1:0] ispr_kmac_msg_bignum_wdata_intg_blanked [Share];

  // MSG SHARE 0

  prim_blanker #(.Width(ExtWLEN)) u_ispr_kmac_msg0_bignum_wdata_blanker (
    .in_i (ispr_bignum_wdata_intg_i),
    .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprKmacMsg0]),
    .out_o(ispr_kmac_msg_bignum_wdata_intg_blanked[0])
  );

  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_kmac_msg0_words
    prim_secded_inv_39_32_enc i_kmac_msg0_secded_enc (
      .data_i (kmac_msg_no_intg_d[0][i_word*32+:32]),
      .data_o (kmac_msg_intg_calc[0][i_word*39+:39])
    );
    prim_secded_inv_39_32_dec i_kmac_msg0_secded_dec (
      .data_i     (kmac_msg_intg_q[0][i_word*39+:39]),
      .data_o     (/* unused because we abort on any integrity error */),
      .syndrome_o (/* unused */),
      .err_o      (kmac_msg_intg_err[0][i_word*2+:2])
    );

    // This write signal is independent of an error in the controller that
    // starts from this module. ispr_wr_commit_i is pulled to 0 when fatal erorr ocurrs
    // which leads to a combinational loop.
    assign kmac_msg_ispr_base_wr[0][i_word] = (ispr_addr_i == IsprKmacMsg0) & ispr_bignum_wr_en_i;

    assign kmac_msg_ispr_wr_en[0][i_word] = kmac_msg_ispr_base_wr[0][i_word] & ispr_wr_commit_i;

    assign kmac_msg_wr_en[0][i_word] = ((kmac_msg_ispr_wr_en[0][i_word] & kmac_msg_write_ready_o[0]) |
                                         sec_wipe_kmac_regs_urnd_i) & ~kmac_msg_wr_stall[0];

    always_ff @(posedge clk_i) begin
      if (kmac_msg_wr_en[0][i_word]) begin
        kmac_msg_intg_q[0][i_word*39+:39] <= kmac_msg_intg_d[0][i_word*39+:39];
      end
    end
    assign kmac_msg_no_intg_q[0][i_word*32+:32] = kmac_msg_intg_q[0][i_word*39+:32];

    always_comb begin
      kmac_msg_no_intg_d[0][i_word*32+:32] = '0;
      unique case (1'b1)
        ispr_init_i: kmac_msg_intg_d[0][i_word*39+:39] = EccZeroWord;
        // Non-encoded inputs have to be encoded before writing to the register.
        sec_wipe_kmac_regs_urnd_i: begin
          kmac_msg_no_intg_d[0][i_word*32+:32] = urnd_data_i[i_word*32+:32];
          kmac_msg_intg_d[0][i_word*39+:39] = kmac_msg_intg_calc[0][i_word*39+:39];
        end
        // Pre-encoded inputs can directly be written to the register.
        default: begin
          kmac_msg_intg_d[0][i_word*39+:39] =
              ispr_kmac_msg_bignum_wdata_intg_blanked[0][i_word*39+:39];
        end
      endcase
    end
  end

  assign kmac_msg_write[0] = (ispr_addr_i == IsprKmacMsg0) & ispr_wr_commit_i;

  // MSG SHARE 1
  logic kmac_msg1_illegal_wr; // Flag to detect illegal write in unmasked mode

  prim_blanker #(.Width(ExtWLEN)) u_ispr_kmac_msg1_bignum_wdata_blanker (
    .in_i (ispr_bignum_wdata_intg_i),
    .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprKmacMsg1]),
    .out_o(ispr_kmac_msg_bignum_wdata_intg_blanked[1])
  );

  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_kmac_msg1_words
    prim_secded_inv_39_32_enc i_kmac_msg1_secded_enc (
      .data_i (kmac_msg_no_intg_d[1][i_word*32+:32]),
      .data_o (kmac_msg_intg_calc[1][i_word*39+:39])
    );
    prim_secded_inv_39_32_dec i_kmac_msg1_secded_dec (
      .data_i     (kmac_msg_intg_q[1][i_word*39+:39]),
      .data_o     (/* unused because we abort on any integrity error */),
      .syndrome_o (/* unused */),
      .err_o      (kmac_msg_intg_err[1][i_word*2+:2])
    );

    assign kmac_msg_ispr_base_wr[1][i_word] = (ispr_addr_i == IsprKmacMsg1) & ispr_bignum_wr_en_i;

    assign kmac_msg_ispr_wr_en[1][i_word] = kmac_msg_ispr_base_wr[1][i_word] & ispr_wr_commit_i;

    assign kmac_msg_wr_en[1][i_word] = (ispr_init_i |
                                     (kmac_msg_ispr_wr_en[1][i_word] & kmac_msg_write_ready_o[1]) |
                                     sec_wipe_kmac_regs_urnd_i) & ~kmac_msg_wr_stall[1];

    always_ff @(posedge clk_i) begin
      if (kmac_msg_wr_en[1][i_word]) begin
        kmac_msg_intg_q[1][i_word*39+:39] <= kmac_msg_intg_d[1][i_word*39+:39];
      end
    end
    assign kmac_msg_no_intg_q[1][i_word*32+:32] = kmac_msg_intg_q[1][i_word*39+:32];

    always_comb begin
      kmac_msg_no_intg_d[1][i_word*32+:32] = '0;
      unique case (1'b1)
        ispr_init_i: kmac_msg_intg_d[1][i_word*39+:39] = EccZeroWord;
        // Non-encoded inputs have to be encoded before writing to the register.
        sec_wipe_kmac_regs_urnd_i: begin
          kmac_msg_no_intg_d[1][i_word*32+:32] = urnd_data_i[i_word*32+:32];
          kmac_msg_intg_d[1][i_word*39+:39] = kmac_msg_intg_calc[1][i_word*39+:39];
        end
        // Pre-encoded inputs can directly be written to the register.
        default: begin
          kmac_msg_intg_d[1][i_word*39+:39] =
              ispr_kmac_msg_bignum_wdata_intg_blanked[1][i_word*39+:39];
        end
      endcase
    end
  end

  assign kmac_msg_write[1] = (ispr_addr_i == IsprKmacMsg1) & ispr_wr_commit_i;

  // If we have a write to share1 during unmasked mode report an error
  always_comb begin
    kmac_msg1_illegal_wr = 1'b0;
    if (~kmac_cfg_mask_mode && |(kmac_msg_ispr_base_wr[1])) begin
      kmac_msg1_illegal_wr = 1'b1;
    end
  end

  // STATUS
  logic [BaseIntgWidth-1:0] kmac_status_intg_q;
  logic [BaseIntgWidth-1:0] kmac_status_intg_d;
  logic [31:0]              kmac_status_no_intg_d;
  logic [1:0]               kmac_status_intg_err;

  // Error handling status for undersized message
  logic kmac_undersized_req_err;

  // Error handling status for oversized message
  logic kmac_oversized_req_err;

  prim_secded_inv_39_32_enc u_kmac_status_secded_enc (
    .data_i (kmac_status_no_intg_d),
    .data_o (kmac_status_intg_d)
  );

  prim_secded_inv_39_32_dec u_kmac_status_secded_dec (
    .data_i     (kmac_status_intg_q),
    .data_o     (/* unused because we abort on any integrity error */),
    .syndrome_o (/* unused */),
    .err_o      (kmac_status_intg_err)
  );

  assign kmac_status_no_intg_d = kmac_new_cfg_q ? 32'b0 : {
    29'b0,
    kmac_app_rsp_i.error,
    kmac_app_rsp_i.ready,
    kmac_app_rsp_i.done
  };

  always_ff @(posedge clk_i) begin
    kmac_status_intg_q <= kmac_status_intg_d;
  end

  // DIGEST SHARE 0

  // Common digest share nets
  logic [DigestRegLen-1:0]              kmac_digest_no_intg_d [Share];
  logic [ExtDigestLen-1:0]              kmac_digest_intg_q    [Share];
  logic [ExtDigestLen-1:0]              kmac_digest_intg_d    [Share];
  logic [ExtDigestLen-1:0]              kmac_digest_intg_calc [Share];
  logic [2*BaseWordsPerDigestLen-1:0]   kmac_digest_intg_err  [Share];
  logic                                 kmac_digest_valid_q;
  logic                                 kmac_digest_wr_en;

  assign kmac_digest_wr_en = ispr_init_i | kmac_app_rsp_i.done | sec_wipe_kmac_regs_urnd_i;

  // Unique share 0 net
  logic [DigestRegLen-1:0]              kmac_digest0_mux_val;

  for (genvar i_word = 0; i_word < BaseWordsPerDigestLen; i_word++) begin : g_kmac_digest0_words
    prim_secded_inv_39_32_enc i_kmac_digest0_secded_enc (
      .data_i (kmac_digest_no_intg_d[0][i_word*32+:32]),
      .data_o (kmac_digest_intg_calc[0][i_word*39+:39])
    );
    prim_secded_inv_39_32_dec i_kmac_digest0_secded_dec (
      .data_i     (kmac_digest_intg_q[0][i_word*39+:39]),
      .data_o     (/* unused because we abort on any integrity error */),
      .syndrome_o (/* unused */),
      .err_o      (kmac_digest_intg_err[0][i_word*2+:2])
    );

    always_ff @(posedge clk_i) begin
      if (kmac_digest_wr_en) begin
        kmac_digest_intg_q[0][i_word*39+:39] <= kmac_digest_intg_d[0][i_word*39+:39];
      end
    end

    always_comb begin
      kmac_digest_no_intg_d[0][i_word*32+:32] = kmac_digest0_mux_val[i_word*32+:32];
      unique case (1'b1)
        ispr_init_i: kmac_digest_intg_d[0][i_word*39+:39] = EccZeroWord;
        // Non-encoded inputs have to be encoded before writing to the register.
        sec_wipe_kmac_regs_urnd_i: begin
          kmac_digest_no_intg_d[0][i_word*32+:32] = urnd_data_i[i_word*32+:32];
          kmac_digest_intg_d[0][i_word*39+:39] = kmac_digest_intg_calc[0][i_word*39+:39];
        end
        // Digest must go through intg_calc before being written into WSR.
        default: begin
          kmac_digest_no_intg_d[0][i_word*32+:32] = kmac_digest0_mux_val[i_word*32+:32];
          kmac_digest_intg_d[0][i_word*39+:39]    = kmac_digest_intg_calc[0][i_word*39+:39];
        end
      endcase
    end
  end

  // This module carefully combines the digest shares and should not be optimized in synthesis
  acc_digest_mux u_digest0_mux (
    .digest_share0_i    (kmac_app_rsp_i.digest_share0[255:0]),
    .digest_share1_i    (kmac_app_rsp_i.digest_share1[255:0]),
    .mask_digest_en_i   (kmac_cfg_mask_mode),
    .digest_share0_wsr_o(kmac_digest0_mux_val)
  );

  // DIGEST SHARE 1
  logic kmac_digest1_illegal_rd; // Flag to detect illegal digest read in unmasked mode

  for (genvar i_word = 0; i_word < BaseWordsPerDigestLen; i_word++) begin : g_kmac_digest1_words
    prim_secded_inv_39_32_enc i_kmac_digest1_secded_enc (
      .data_i (kmac_digest_no_intg_d[1][i_word*32+:32]),
      .data_o (kmac_digest_intg_calc[1][i_word*39+:39])
    );
    prim_secded_inv_39_32_dec i_kmac_digest1_secded_dec (
      .data_i     (kmac_digest_intg_q[1][i_word*39+:39]),
      .data_o     (/* unused because we abort on any integrity error */),
      .syndrome_o (/* unused */),
      .err_o      (kmac_digest_intg_err[1][i_word*2+:2])
    );

    always_ff @(posedge clk_i) begin
      if (kmac_digest_wr_en) begin
        kmac_digest_intg_q[1][i_word*39+:39] <= kmac_digest_intg_d[1][i_word*39+:39];
      end
    end

    always_comb begin
      kmac_digest_no_intg_d[1][i_word*32+:32] = kmac_app_rsp_i.digest_share1[i_word*32+:32];
      unique case (1'b1)
        ispr_init_i: kmac_digest_intg_d[1][i_word*39+:39] = EccZeroWord;
        // Non-encoded inputs have to be encoded before writing to the register.
        sec_wipe_kmac_regs_urnd_i: begin
          kmac_digest_no_intg_d[1][i_word*32+:32] = urnd_data_i[i_word*32+:32];
          kmac_digest_intg_d[1][i_word*39+:39] = kmac_digest_intg_calc[1][i_word*39+:39];
        end
        // Digest must go through intg_calc before being written into WSR.
        default: begin
          kmac_digest_no_intg_d[1][i_word*32+:32] = kmac_app_rsp_i.digest_share1[i_word*32+:32];
          kmac_digest_intg_d[1][i_word*39+:39]    = kmac_digest_intg_calc[1][i_word*39+:39];
        end
      endcase
    end
  end

  // Check if there is a read from DIGEST SHARE 1 outside of masked mode
  always_comb begin
    kmac_digest1_illegal_rd = 1'b0;
    if (~kmac_cfg_mask_mode && ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1]) begin
      kmac_digest1_illegal_rd = 1'b1;
    end
  end

  // KMAC EAGER DIGEST REFRESH
  // Common digest share interface to cotrol valids and app_o.next
  logic       kmac_digest_rd_next;
  logic [1:0] sha_digest_rsp_cnt;

  assign kmac_digest_valid_o = kmac_digest_valid_q;

  // Make an FSM to control eager KMAC refresh
  // Need to have read from both WSR in order to fetch the next digests
  // Consecutive reads from the same digest share are legal but will not trigger a
  // new digest to be shifted from KMAC.

  // If the next eager KMAC refresh will trigger a manual run we will wait for an
  // instruction call to read. This lowers the overhead of incorectly requesting a
  // new digest and needing to wait for Keccak to finish before the next transaction.

  logic [2:0] digest_word_idx_q, digest_word_idx_d;
  logic reset_digest_word;
  logic [2:0] max_digest_words;
  logic [1:0] permutation_ctr;
  logic incr_permutation_ctr, reset_permutation_ctr;
  logic valid_eager;
  logic clear_eager_digest;

  kmac_eager_state_e eager_state_d, eager_state_q;

  always_comb begin : kmac_eager_next_fsm
    // Default assignments
    eager_state_d = eager_state_q;
    kmac_digest_rd_next = 1'b0;
    incr_permutation_ctr = 1'b0;
    clear_eager_digest = 1'b0;
    reset_digest_word = 1'b0;

    unique case (eager_state_q)
      StDigestWait: begin
        // Determine if there is a read from digest 0 or digest 1
        if (kmac_digest_valid_q && ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest0]) begin
          if (~kmac_cfg_mask_mode) begin
            // When in unmasked mode we can immediately refresh unless it triggers a manual run
            if (valid_eager) begin
              eager_state_d = StDigestWait;
              kmac_digest_rd_next = 1'b1;
            end else begin
              // Go to the StDigestEagerWait state until we explicitely request a new read
              eager_state_d = StDigestEagerWait;
              incr_permutation_ctr = 1'b1;
              clear_eager_digest = 1'b1;
            end
          end else begin
            eager_state_d = StDigestShare0;
          end
        end else if (kmac_digest_valid_q && ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1]) begin
          eager_state_d = StDigestShare1;
        end
      end

      // We have already read from DigestShare0, now we wait for a read from DigestShare1
      StDigestShare0: begin
        if (kmac_digest_valid_q && ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1]) begin
          if (valid_eager) begin
            eager_state_d = StDigestWait;
            kmac_digest_rd_next = 1'b1;
          end else begin
              // Go to the StDigestEagerWait state until we explicitely request a new read
            eager_state_d = StDigestEagerWait;
            incr_permutation_ctr = 1'b1;
            clear_eager_digest = 1'b1;
          end
        end
      end

      // We have already read from DigestShare1, now we wait for a read from DigestShare0
      StDigestShare1: begin
        if (kmac_digest_valid_q && ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest0]) begin
          if (valid_eager) begin
            eager_state_d = StDigestWait;
            kmac_digest_rd_next = 1'b1;
          end else begin
              // Go to the StDigestEagerWait state until we explicitely request a new read
            eager_state_d = StDigestEagerWait;
            incr_permutation_ctr = 1'b1;
            clear_eager_digest = 1'b1;
          end
        end
      end

      // We have exhausted the Keccak state and will not request a manual run until we are
      // guarenteed to need more
      StDigestEagerWait: begin
        if (ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest0]) begin
          // Go to DigestShare0 or Wait state depending on masked configuration
          if (~kmac_cfg_mask_mode) begin
            eager_state_d = StDigestWait;
          end else begin
            eager_state_d = StDigestShare0;
          end
          // Trigger the next read and reset the digest word count
          kmac_digest_rd_next = 1'b1;
          reset_digest_word = 1'b1;
        end else if (ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1]) begin
          eager_state_d = StDigestShare1;
          // Trigger the next read and reset the digest word count
          kmac_digest_rd_next = 1'b1;
          reset_digest_word = 1'b1;
        end
      end
      default: eager_state_d = StDigestWait;
    endcase
  end

  // Comb component of counter for the number of digest reads from the current Keccak State
  always_comb begin
    digest_word_idx_d = digest_word_idx_q;
    if (kmac_app_rsp_i.done) begin
      digest_word_idx_d = digest_word_idx_q + 1'b1;
    end
  end

  // Flop component of counter for the number of digest reads from the current Keccak State
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) digest_word_idx_q <= '0;
    else if (kmac_new_cfg_q || reset_digest_word) begin
      digest_word_idx_q <= '0;
    end else begin
      digest_word_idx_q <= digest_word_idx_d;
    end
  end

  // Logic to set the valid_eager signal to determine if we can eager trigger
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      valid_eager <= 1'b0;
      reset_permutation_ctr <= 1'b0;
    end else begin
      // If it is the 4th permutation from KMAC there is a fifth digest word available
      // in the KMAC output buffer before needing to trigger a manual run
      if (digest_word_idx_d == max_digest_words && permutation_ctr == 2'h3) begin
        valid_eager <= 1'b1;
        reset_permutation_ctr <= 1'b0;
      // For all other permutations we need to trigger a new manual run
      end else if (digest_word_idx_d == max_digest_words) begin
        valid_eager <= 1'b0;
        reset_permutation_ctr <= 1'b0;
      end else begin
        // Digest word idx will only be greater when the permutation_ctr == 2'h3
        if (digest_word_idx_d > max_digest_words) begin
          valid_eager <= 1'b0;
          reset_permutation_ctr <= 1'b1;
        end else begin
          valid_eager <= 1'b1;
          reset_permutation_ctr <= 1'b0;
        end
      end
    end
  end

  // Control the permutation index for keccak states and XOFs with ACC
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      permutation_ctr <= 2'h0;
    end else if (reset_permutation_ctr || kmac_new_cfg_q) begin
      permutation_ctr <= 2'h0;
    end else if (incr_permutation_ctr) begin
      permutation_ctr <= permutation_ctr + 1'b1;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      eager_state_q <= StDigestWait;
    end else if (kmac_new_cfg_q) begin
      eager_state_q <= StDigestWait;
    end else begin
      eager_state_q <= eager_state_d;
    end
  end

  // Set when the received digest is valid/new
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_digest_valid_q <= 1'b0;
    end else if (kmac_digest_rd_next || kmac_new_cfg_q || clear_eager_digest) begin
      kmac_digest_valid_q <= 1'b0;
    end else if (kmac_app_rsp_i.done) begin
      kmac_digest_valid_q <= 1'b1;
    end
  end

  // Only in SHA256 or SHA512 mode accumulate and limit the number of responses
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      sha_digest_rsp_cnt <= 2'b0;
    end else if (kmac_new_cfg_q) begin
      sha_digest_rsp_cnt <= 2'b0;
    end else if (sha3_pkg::sha3_mode_e'(kmac_cfg_intg_q[1:0]) == sha3_pkg::Sha3) begin
      if (kmac_digest_rd_next) begin
        sha_digest_rsp_cnt <= sha_digest_rsp_cnt + 1'b1;
      end
    end
  end

  // MSG INTERFACE
  sha3_pkg::sha3_mode_e           kmac_cfg_sha3_mode;
  sha3_pkg::keccak_strength_e     kmac_cfg_keccak_strength;
  logic [10:0]                    kmac_cfg_unused_msg_len;
  logic [14:0]                    kmac_cfg_msg_len;
  logic [11:0]                    kmac_cfg_msg_len_words;
  logic [2:0]                     kmac_cfg_msg_len_bytes;

  logic                           kmac_msg_err_clr;
  logic                           kmac_msg_err_clr_q;

  // FIFO packer and counter shares
  logic [11:0]                    kmac_msg_ctr             [Share];
  logic                           kmac_msg_ctr_err         [Share];
  logic [WLEN-1:0]                kmac_msg_fifo_wdata_mask        ;
  logic                           kmac_msg_fifo_wready     [Share];
  logic [WLEN-1:0]                kmac_msg_fifo_wdata      [Share];
  logic                           kmac_msg_fifo_rvalid     [Share];
  logic                           kmac_msg_fifo_rready     [Share];
  logic [kmac_pkg::MsgWidth-1:0]  kmac_msg_fifo_rdata      [Share];
  logic [kmac_pkg::MsgWidth-1:0]  kmac_msg_fifo_rdata_mask [Share];
  logic                           kmac_msg_fifo_flush             ;
  logic                           kmac_msg_fifo_clr               ;

  logic       packer_ctr_last       [Share];
  logic [7:0] packer_rdata_mask     [Share];
  logic [3:0] packer_rdata_mask_cnt [Share];

  // Signals for last from packer
  logic                           kmac_last_msg_all_bytes_valid;
  logic [kmac_pkg::MsgStrbW-1:0]  kmac_last_msg_strb;
  logic msg_last_words [Share];
  logic msg_last_bytes [Share];

  // Config and status signals
  logic kmac_app_active;
  logic kmac_app_last;
  logic kmac_msg_active_q;
  logic kmac_cfg_active_q;
  logic kmac_write_cfg_to_app;
  logic kmac_msg_last;
  logic kmac_idle_q;
  logic kmac_cfg_done;
  logic kmac_app_cfg_sent;
  logic kmac_ispr;

  // AppIntf error handling signals
  logic kmac_msg_req_err;
  logic kmac_msg_mask_err;
  logic kmac_fifo_deadlock;
  logic kmac_pending_last;
  logic kmac_inject_last_err;
  logic kmac_undersized_req_err_q;
  logic kmac_undersized_req_err_pe;

  kmac_undersized_state_e kmac_err_st_d, kmac_err_st_q;
  // Oversized error flag if last has already been sent and there is an additional fifo valid
  // Need to add a case when the fifo rvalid mask is greater than the last word strb
  logic last_word_oversized;
  logic rw_after_last;
  logic write_during_last;
  logic not_full_word;
  logic packer_oversized_last;

  // Combined FIFO ready
  logic kmac_msg_fifos_valid;

  assign kmac_cfg_sha3_mode       = sha3_pkg::sha3_mode_e'(kmac_cfg_intg_q[1:0]);
  assign kmac_cfg_keccak_strength = sha3_pkg::keccak_strength_e'(kmac_cfg_intg_q[4:2]);
  assign kmac_cfg_done            = kmac_cfg_intg_q[31];
  assign kmac_cfg_mask_mode       = kmac_cfg_intg_q[20];
  assign kmac_cfg_msg_len         = kmac_cfg_intg_q[19:5];
  assign kmac_cfg_msg_len_words   = kmac_cfg_msg_len[14:3];
  assign kmac_cfg_msg_len_bytes   = kmac_cfg_msg_len[2:0];
  assign kmac_msg_err_clr         = kmac_app_rsp_i.error
                                    | sec_wipe_kmac_regs_urnd_i
                                    | kmac_msg_ctr_err[0]
                                    | kmac_msg_ctr_err[1];

  assign kmac_ispr = sec_wipe_kmac_regs_urnd_i | ispr_init_i;

  always_comb begin
    max_digest_words = kmac_pkg::compute_max_digest(kmac_cfg_keccak_strength);
  end

  // We speculatively fetch the next digest but this is illegal for non XOF
  // modes. As such SHA will need to limit the speculative fetch based on strength.
  logic kmac_next_sha;

  always_comb begin
    kmac_next_sha = 1'b0;
    unique case (kmac_cfg_sha3_mode)
      sha3_pkg::Sha3: begin
        if (kmac_cfg_keccak_strength == sha3_pkg::L256) begin
          kmac_next_sha = 1'b0; // There will never be a new read
        end else if (kmac_cfg_keccak_strength == sha3_pkg::L512) begin
          if (sha_digest_rsp_cnt < 1) begin
            kmac_next_sha = 1'b1;
          end else begin
            kmac_next_sha = 1'b0;
          end
        end
      end
      sha3_pkg::Shake: begin
        kmac_next_sha = 1'b1;
      end
      sha3_pkg::CShake: begin
        kmac_next_sha = 1'b1;
      end
      default: begin
        kmac_next_sha = 1'b0;
      end
    endcase
  end

  // Create the strb for the last word in msg request
  assign kmac_last_msg_all_bytes_valid = &(~kmac_cfg_msg_len_bytes);
  for (genvar i_bit = 1; i_bit < kmac_pkg::MsgStrbW+1; i_bit++) begin : gen_kmac_strb
    assign kmac_last_msg_strb[i_bit-1] = kmac_last_msg_all_bytes_valid
                                         | (i_bit <= kmac_cfg_msg_len_bytes);
  end

  // Set flag for a new KMAC cfg to indicate start/end of transaction
  // Used to ensure FIFO is flushed and set bounds of transaction
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_new_cfg_q <= 1'b0;
    end else if (kmac_cfg_wr_en & !kmac_ispr) begin
      kmac_new_cfg_q <= 1'b1;
    end else begin
      kmac_new_cfg_q <= 1'b0;
    end
  end

  // If there is an error we need to flush the remainder of the FIFO under the assumption
  // that KMAC won't be asserting a ready signal to ACC. Latch the error flag until a new
  // config is written to ACC and use this to empty the FIFO and prepare for the next transaction.
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_msg_err_clr_q <= 1'b0;
    end else if (kmac_cfg_wr_en) begin
      kmac_msg_err_clr_q <= 1'b0;
    end else if (kmac_msg_err_clr) begin
      kmac_msg_err_clr_q <= 1'b1;
    end
  end

  // Set cfg and msg status flags for transaction
  // CFG is active from start of config until end of transaction
  // MSG is active after the cfg word is sent
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_msg_active_q <= 1'b0;
      kmac_cfg_active_q <= 1'b0;
    end else if (kmac_new_cfg_q) begin
      kmac_msg_active_q <= 1'b0;
      kmac_cfg_active_q <= 1'b1;
    end else if (kmac_msg_err_clr || kmac_idle_q) begin
      kmac_msg_active_q <= 1'b0;
      kmac_cfg_active_q <= 1'b0;
    end else if (kmac_msg_fifo_wready[0]) begin //kmac_app_cfg_sent
      kmac_msg_active_q <= kmac_cfg_active_q;
    end
  end

  // Message is valid when there is ISPR write to the MSG WSR
  // Value is held until it is written into the fifo at the first wready signal
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_msg_valid_q[0] <= 1'b0;
    end else if (|(kmac_msg_wr_en[0]) & !kmac_ispr) begin
      kmac_msg_valid_q[0] <= 1'b1;
    end else if (kmac_msg_fifo_wready[0]) begin
      kmac_msg_valid_q[0] <= 1'b0;
    end
  end

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_msg_valid_q[1] <= 1'b0;
    end else if (|(kmac_msg_wr_en[1]) & !kmac_ispr & kmac_cfg_mask_mode) begin
      kmac_msg_valid_q[1] <= 1'b1;
    end else if (kmac_msg_fifo_wready[1]) begin
      kmac_msg_valid_q[1] <= 1'b0;
    end
  end

  // KMAC is idle when CFG WSR bit [31] is 1
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_idle_q <= 1'b1;
    end else if (kmac_cfg_done) begin
      kmac_idle_q <= 1'b1;
    end else begin
      kmac_idle_q <= 1'b0;
    end
  end

  // Internal status flag to track when the configuration word has been sent to KMAC
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_app_cfg_sent <= 1'b0;
    end else if (~kmac_app_req_o.hold) begin // Once the message is complete drop flag
      kmac_app_cfg_sent <= 1'b0;
    end else if (kmac_cfg_active_q) begin
      if (kmac_app_rsp_i.ready) begin
        kmac_app_cfg_sent <= 1'b1;
      end
    end else begin
      kmac_app_cfg_sent <= 1'b0;
    end
  end

  // Translates the 5-bit decimal mask from PW WSR to 256-bit bit wise mask for APP FIFO
  always_comb begin
    kmac_msg_fifo_wdata_mask = '0;
    if (kmac_pw_mask == 0) begin
      kmac_msg_fifo_wdata_mask = 256'b0;
    end else begin
      kmac_msg_fifo_wdata_mask = ~({256{1'b1}} << (kmac_pw_mask * 8));
    end
  end

  // Convert the number of 1's in byte mask to decimal value for comparison
  // with CFG WSR partial word byte field
  always_comb begin
    packer_rdata_mask_cnt[0] = '0;
    packer_rdata_mask_cnt[1] = '0;
    for (int i = 0; i < kmac_pkg::MsgStrbW; i++) begin
      // collapse each 8-bit chunk into one strb bit
      packer_rdata_mask[0][i] = |kmac_msg_fifo_rdata_mask[0][i*8 +: 8];
      packer_rdata_mask[1][i] = |kmac_msg_fifo_rdata_mask[1][i*8 +: 8];
    end
    for (int i = 0; i < 8; i++) begin
      packer_rdata_mask_cnt[0] += {3'b0, packer_rdata_mask[0][i]};
      packer_rdata_mask_cnt[1] += {3'b0, packer_rdata_mask[1][i]};
    end
  end

  // Internal copy of acc_controller stall signal to determine pending msg writes
  assign kmac_msg_wr_stall[0] = (kmac_msg_write[0] & (~kmac_msg_fifo_wready[0]));
  assign kmac_msg_wr_stall[1] = (kmac_msg_write[1] & (~kmac_msg_fifo_wready[1]));

  // When reading the return digest the message has already been sent and any remainder is cleared
  assign kmac_msg_fifo_clr = kmac_sent_last &&
                             ((ispr_addr_i == IsprKmacDigest0) | (ispr_addr_i == IsprKmacDigest1))
                             && !kmac_msg_pending_write_o[0] && !kmac_msg_pending_write_o[1];

  // MSG SHARE 0 Packer and Ctr
  // Prim packer is used to send full words until the final word in msg request
  prim_packer #(
    .InW  (WLEN),
    .OutW (kmac_pkg::MsgWidth)
  ) u_kmac_msg_fifo (
    .clk_i,
    .rst_ni,

    .valid_i      (kmac_msg_fifo_wvalid[0]),
    .data_i       (kmac_msg_fifo_wdata[0]),
    .mask_i       (kmac_msg_fifo_wdata_mask),
    .ready_o      (kmac_msg_fifo_wready[0]),

    .valid_o      (kmac_msg_fifo_rvalid[0]),
    .data_o       (kmac_msg_fifo_rdata[0]),
    .mask_o       (kmac_msg_fifo_rdata_mask[0]),
    .ready_i      (kmac_msg_fifo_rready[0]),

    // kmac_msg_err_clr is for internal ACC error to empty the FIFO
    // kmac_msg_fifo_flush reads a partial word at the end of the msg
    // kmac_msg_fifo_clr ensures the fifo is empty outside of an active msg
    .flush_i      (kmac_msg_err_clr || kmac_msg_fifo_flush || kmac_msg_fifo_clr),
    .flush_done_o (),

    .err_o        ()
  );

  // Prim counter is used to keep track of the message size sent
  prim_count #(
    .Width (12),
    .EnableAlertTriggerSVA('0)
  ) u_kmac_msg0_ctr (
    .clk_i,
    .rst_ni,

    .clr_i              (kmac_msg_err_clr || kmac_new_cfg_q || kmac_sent_last),
    .set_i              (1'b0),
    .set_cnt_i          ({(12){1'b0}}),
    .incr_en_i          (kmac_msg_fifo_rvalid[0] & kmac_app_rsp_i.ready & kmac_msg_fifo_rready[0]),
    .decr_en_i          (1'b0),
    .step_i             ({{(11){1'b0}}, {1'b1}}),
    .commit_i           (1'b1),
    .cnt_o              (kmac_msg_ctr[0]),
    .cnt_after_commit_o (/* unused */),
    .err_o              (kmac_msg_ctr_err[0])
  );

  // MSG SHARE 1 Packer and Ctr
  prim_packer #(
    .InW  (WLEN),
    .OutW (kmac_pkg::MsgWidth)
  ) u_kmac_msg1_fifo (
    .clk_i,
    .rst_ni,

    .valid_i      (kmac_msg_fifo_wvalid[1]),
    .data_i       (kmac_msg_fifo_wdata[1]),
    .mask_i       (kmac_msg_fifo_wdata_mask),
    .ready_o      (kmac_msg_fifo_wready[1]),

    .valid_o      (kmac_msg_fifo_rvalid[1]),
    .data_o       (kmac_msg_fifo_rdata[1]),
    .mask_o       (kmac_msg_fifo_rdata_mask[1]),
    .ready_i      (kmac_msg_fifo_rready[1]),

    // kmac_msg_err_clr is for internal ACC error to empty the FIFO
    // kmac_msg_fifo_flush reads a partial word at the end of the msg
    // kmac_msg_fifo_clr ensures the fifo is empty outside of an active msg
    .flush_i      (kmac_msg_err_clr || kmac_msg_fifo_flush || kmac_msg_fifo_clr),
    .flush_done_o (),

    .err_o        ()
  );

  prim_count #(
    .Width (12),
    .EnableAlertTriggerSVA('0)
  ) u_kmac_msg1_ctr (
    .clk_i,
    .rst_ni,

    .clr_i              (kmac_msg_err_clr || kmac_new_cfg_q || kmac_sent_last),
    .set_i              (1'b0),
    .set_cnt_i          ({(12){1'b0}}),
    .incr_en_i          (kmac_msg_fifo_rvalid[1] & kmac_app_rsp_i.ready & kmac_msg_fifo_rready[1]),
    .decr_en_i          (1'b0),
    .step_i             ({{(11){1'b0}}, {1'b1}}),
    .commit_i           (1'b1),
    .cnt_o              (kmac_msg_ctr[1]),
    .cnt_after_commit_o (/* unused */),
    .err_o              (kmac_msg_ctr_err[1])
  );

  // Check if we have a FIFO deadlock
  always_comb begin
    kmac_fifo_deadlock = 1'b0;
    if (kmac_cfg_mask_mode) begin
      if (
        (|kmac_msg_ispr_base_wr[0] & ~kmac_msg_fifo_wready[0]) &
        ~kmac_msg_fifo_rvalid[1] & ~kmac_msg_valid_q[1]
      ) begin
        kmac_fifo_deadlock = 1'b1;
      end
      if (
        (|kmac_msg_ispr_base_wr[1] & ~kmac_msg_fifo_wready[1]) &
        ~kmac_msg_fifo_rvalid[0] & ~kmac_msg_valid_q[0]
      ) begin
        kmac_fifo_deadlock = 1'b1;
      end
    end
  end

  // All fifos for masked mode are rvalid
  assign kmac_msg_fifos_valid = kmac_cfg_mask_mode ?
                                kmac_msg_fifo_rvalid[0] && kmac_msg_fifo_rvalid[1] :
                                kmac_msg_fifo_rvalid[0];

  // Ensure that the read mask is at least the size of the cfg before asserting last
  assign packer_ctr_last[0] = (packer_rdata_mask_cnt[0] >= {1'b0, kmac_cfg_msg_len_bytes});
  assign packer_ctr_last[1] = (packer_rdata_mask_cnt[1] >= {1'b0, kmac_cfg_msg_len_bytes});

  // If it is time for the final word and there is a partial word we need to flush it out
  assign kmac_msg_fifo_flush   = (kmac_msg_last && (kmac_cfg_msg_len_bytes != 3'h0) &&
                                 (~kmac_msg_fifo_rvalid[0] && ~kmac_msg_fifo_rvalid[1]));

  assign kmac_write_cfg_to_app =  kmac_cfg_active_q && (~kmac_msg_active_q | ~kmac_app_cfg_sent) &&
                                  ~kmac_idle_q;

  // fifo share 0 write iface
  assign kmac_msg_fifo_wdata[0]  = kmac_msg_no_intg_q[0];
  assign kmac_msg_fifo_wvalid[0] =
      kmac_cfg_active_q && kmac_msg_valid_q[0] && kmac_msg_fifo_wready[0] &&
      ~kmac_msg_fifo_flush && ~kmac_sent_last && ~kmac_msg_last;

  assign kmac_msg_write_ready_o[0] = kmac_msg_fifo_wready[0];

  // fifo share 0 read iface
  // KMAC must be ready to receive data and we should only fetch the next word if both shares
  // are asserted valid on the AppIntf. The FIFO may have to wait during writes to the other share.
  assign kmac_msg_fifo_rready[0] = (kmac_app_rsp_i.ready & ~kmac_write_cfg_to_app &
                                    kmac_msg_fifo_rvalid[0] & kmac_app_req_o.valid) |
                                   (kmac_sent_last | kmac_msg_err_clr_q);

  // fifo share 1 write iface
  assign kmac_msg_fifo_wdata[1]  = kmac_msg_no_intg_q[1];
  assign kmac_msg_fifo_wvalid[1] =
      kmac_cfg_active_q && kmac_msg_valid_q[1] && kmac_msg_fifo_wready[1] &&
      ~kmac_msg_fifo_flush && ~kmac_sent_last && ~kmac_msg_last;

  assign kmac_msg_write_ready_o[1] = kmac_msg_fifo_wready[1];

  // fifo share 1 read iface
  assign kmac_msg_fifo_rready[1] = (kmac_app_rsp_i.ready & ~kmac_write_cfg_to_app &
                                  kmac_msg_fifo_rvalid[1] & kmac_app_req_o.valid) |
                                 (kmac_sent_last | kmac_msg_err_clr_q);

  assign kmac_msg_pending_write_o[0] = kmac_msg_valid_q[0] && ~kmac_sent_last;
  assign kmac_msg_pending_write_o[1] = kmac_msg_valid_q[1] && ~kmac_sent_last;

  assign msg_last_words[0] = (kmac_msg_ctr[0] >= kmac_cfg_msg_len_words - 1) &&
                              kmac_msg_fifo_rvalid[0];
  assign msg_last_bytes[0] = ((kmac_msg_ctr[0] >= kmac_cfg_msg_len_words) && packer_ctr_last[0]);
  assign msg_last_words[1] = (kmac_msg_ctr[1] >= kmac_cfg_msg_len_words - 1) &&
                              kmac_msg_fifo_rvalid[1];
  assign msg_last_bytes[1] = ((kmac_msg_ctr[1] >= kmac_cfg_msg_len_words) && packer_ctr_last[1]);

  always_comb begin
    if (kmac_cfg_msg_len_bytes == 3'h0) begin
      if (kmac_cfg_mask_mode) kmac_msg_last = msg_last_words[0] & msg_last_words[1];
      else                    kmac_msg_last = msg_last_words[0];
    end else begin
      if (kmac_cfg_mask_mode) kmac_msg_last = msg_last_bytes[0] & msg_last_bytes[1];
      else                    kmac_msg_last = msg_last_bytes[0];
    end
  end

  // Compute the assignment for kmac_app_req_o.hold
  assign kmac_app_active = kmac_cfg_active_q & ~kmac_new_cfg_q & ~kmac_cfg_done;

  // Compute the assignment for kmac_app_req_o.last
  assign kmac_app_last = kmac_inject_last_err | (kmac_msg_fifos_valid & kmac_msg_last);

  // When there is an undersized message we artificially inject a last valid to finish the message
  assign kmac_app_req_o.valid = (kmac_write_cfg_to_app || kmac_inject_last_err) ?
                                1'b1 : kmac_msg_fifos_valid && ~kmac_new_cfg_q &&
                                       ~kmac_sent_last && ~kmac_msg_err_clr_q;

  // The first word contains the cfg otherwise send the body
  assign kmac_app_req_o.data_share0 = kmac_write_cfg_to_app ?
                                      {59'b0, kmac_cfg_keccak_strength, kmac_cfg_sha3_mode} :
                                      kmac_msg_fifo_rdata[0];
  assign kmac_app_req_o.data_share1 = (kmac_write_cfg_to_app | ~kmac_cfg_mask_mode) ?
                                      64'b0 : kmac_msg_fifo_rdata[1];

  // The strb will always be 8'hFF except for the CFG and last word
  assign kmac_app_req_o.strb  = kmac_write_cfg_to_app ?
                                8'h01 : kmac_app_last ?
                                kmac_last_msg_strb : {(kmac_pkg::MsgStrbW){1'b1}};

  // When there is an undersized message we artifically inject a last signal to finish the message
  assign kmac_app_req_o.last  = kmac_app_last;

  // If we request an additional digest send a next to KMAC
  assign kmac_app_req_o.next  = kmac_digest_rd_next & kmac_next_sha;

  // Hold will remain active for duration of transaction unless an internal error occurs
  assign kmac_app_req_o.hold  = kmac_app_active;

  // check for incomplete msg with pending digest
  // Latch for last in current transaction
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_pending_last <= 1'b0;
      kmac_sent_last <= 1'b0;
    end else begin
      // Either we observed a valid last or we artificially created a last
      if ((kmac_msg_fifo_rvalid[0] & kmac_msg_last) | kmac_inject_last_err) begin
        kmac_pending_last <= 1'b1; // Prepared to send the final word
        if (kmac_app_rsp_i.ready) begin
          kmac_sent_last <= 1'b1;
        end
      end else if (kmac_cfg_wr_en) begin
        // Clear any last flags after a new cfg is written
        kmac_pending_last <= 1'b0;
        kmac_sent_last <= 1'b0;
      end
    end
  end

  // If current instruction is KMAC Digest check if KMAC received all data
  // There should be no outstanding transactions to write into the FIFO
  // There should not be any new words being written or read to/from the FIFO
  // The FIFO should not be in a flush cycle
  always_comb begin
    kmac_msg_req_err = 1'b0;
    if (
      (ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest0] |
       ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1]) &&
       kmac_app_active
    ) begin
      kmac_msg_req_err = !(kmac_msg_pending_write_o[0] | kmac_msg_pending_write_o[1]) &&
                         !(kmac_msg_fifos_valid) &&
                         !kmac_msg_fifo_flush &&
                         !(kmac_msg_fifo_wvalid[0] | kmac_msg_fifo_wvalid[1]);
    end
  end

  // If we have not received a last see if there is an error
  assign kmac_undersized_req_err = kmac_msg_req_err & ~kmac_pending_last;

  // Register the undersized req err to compute a posedge
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_undersized_req_err_q <= 1'b0;
    end else begin
      kmac_undersized_req_err_q <= kmac_undersized_req_err;
    end
  end

  // Posedge of undersize kmac req err
  assign kmac_undersized_req_err_pe = ~kmac_undersized_req_err_q && kmac_undersized_req_err;

  // Combinatorial state machine for oversized message computation
  always_comb begin
    kmac_err_st_d = kmac_err_st_q;
    kmac_inject_last_err = 1'b0;
    unique case (kmac_err_st_q)
      StIdle: begin
        // At the first appearance of an undersized message during a tranasaction
        // set a flag to inject an artificial last word and wait until KMAC is ready
        if (kmac_undersized_req_err_pe) begin
          kmac_inject_last_err = 1'b1;
          if (~kmac_app_rsp_i.ready) begin
            kmac_err_st_d = StPendingReady;
          end
        end
      end
      StPendingReady: begin
        // Continue holding last word until acknowledgement from KMAC
        kmac_inject_last_err = 1'b1;
        if (kmac_app_rsp_i.ready) begin
          kmac_err_st_d = StIdle;
        end
      end
      default: begin
        kmac_err_st_d = StIdle;
        kmac_inject_last_err = 1'b0;
      end
    endcase
  end

  // Register the state
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      kmac_err_st_q <= StIdle;
    end else begin
      kmac_err_st_q <= kmac_err_st_d;
    end
  end

  always_comb begin
    kmac_msg_mask_err = 1'b0;
    if (kmac_cfg_mask_mode) begin
      if (kmac_app_req_o.last & kmac_app_req_o.valid) begin
        if (packer_rdata_mask_cnt[0] != packer_rdata_mask_cnt[1]) begin
          kmac_msg_mask_err = 1'b1;
        end else begin
          kmac_msg_mask_err = 1'b0;
        end
      end
    end
  end

  // The cfg reads 0 when it is a full word which means the mask is 8 so we must skip evaluation
  // at these sizes, otherwise check if mask is greater than the cfg
  always_comb begin
    not_full_word = 1'b0;
    if (kmac_cfg_mask_mode) begin
      not_full_word = ~(packer_rdata_mask_cnt[0] == 4'h8 & kmac_cfg_msg_len_bytes == 3'h0) &
                      ~(packer_rdata_mask_cnt[1] == 4'h8 & kmac_cfg_msg_len_bytes == 3'h0);
    end else begin
      not_full_word = ~(packer_rdata_mask_cnt[0] == 4'h8 & kmac_cfg_msg_len_bytes == 3'h0);
    end
  end
  assign packer_oversized_last =
      not_full_word & ((packer_rdata_mask_cnt[0] > {1'b0, kmac_cfg_msg_len_bytes}) |
                       (packer_rdata_mask_cnt[1] > {1'b0, kmac_cfg_msg_len_bytes}));

  assign last_word_oversized    = kmac_msg_last & packer_oversized_last;
  // Read or write to/from FIFO that occurs after last
  assign rw_after_last = kmac_sent_last & ((kmac_msg_fifo_rvalid[0] | kmac_msg_valid_q[0]) |
                                           (kmac_msg_fifo_rvalid[1] | kmac_msg_valid_q[1]));
  // There is still a pending write to the FIFO while last is being asserted after flush
  assign write_during_last      = kmac_app_last & (kmac_msg_valid_q[0] | kmac_msg_valid_q[1]);
  // Injecting an artificial last may impact the write_during_last flag so we check that the
  // message isn't undersized before raising this flag
  assign kmac_oversized_req_err = (rw_after_last | write_during_last) | last_word_oversized;

  assign kmac_intf_fatal_error_o = kmac_app_rsp_i.error | kmac_undersized_req_err |
                                   kmac_oversized_req_err | kmac_fifo_deadlock |
                                   kmac_msg_mask_err | kmac_msg_ctr_err[0] | kmac_msg_ctr_err[1];
  assign kmac_intf_recov_error_o = kmac_digest1_illegal_rd | kmac_msg1_illegal_wr;

  assign kmac_intg_err_o = |{kmac_msg_intg_err[0], kmac_msg_intg_err[1],
                             kmac_digest_intg_err[0], kmac_digest_intg_err[1],
                             kmac_cfg_intg_err,
                             kmac_status_intg_err};

  // TODO: TMP INTG outputs to be replaced by local mux
  assign kmac_cfg_intg_o    = kmac_cfg_intg_q[31:0];
  assign kmac_status_intg_o = kmac_status_intg_q[31:0];
  assign kmac_msg_intg_o    = kmac_msg_intg_q;
  assign kmac_digest_intg_o = kmac_digest_intg_q;

  // Tie off unused bits from pqc signals
  logic unused_pqc_bits;
  assign unused_pqc_bits =
      ^{ispr_kmac_cfg_bignum_wdata_intg_blanked[311:39],
        ispr_kmac_pw_bignum_wdata_intg_blanked[311:39],
        kmac_pw_intg_err};

  // KMAC CFG ISPR Blanking
  `ASSERT(BlankingIsprKmacCfg_A,
          !(|kmac_cfg_wr_en) |->
          ispr_kmac_cfg_bignum_wdata_intg_blanked == '0,
          clk_i, !rst_ni || ispr_predec_error_i || alu_predec_error_i || !operation_commit_i)

  // KMAC MSG0 ISPR Blanking
  `ASSERT(BlankingIsprKmacMsg0A,
          !((|kmac_msg_wr_en[0]) |
          ispr_predec_bignum_i.ispr_wr_en[IsprKmacMsg0]) |->
          ispr_kmac_msg_bignum_wdata_intg_blanked[0] == '0,
          clk_i, !rst_ni || ispr_predec_error_i || alu_predec_error_i || !operation_commit_i)

  // KMAC MSG1 ISPR Blanking
  `ASSERT(BlankingIsprKmacMsg1A,
          !((|kmac_msg_wr_en[1]) |
          ispr_predec_bignum_i.ispr_wr_en[IsprKmacMsg1]) |->
          ispr_kmac_msg_bignum_wdata_intg_blanked[1] == '0,
          clk_i, !rst_ni || ispr_predec_error_i || alu_predec_error_i || !operation_commit_i)

endmodule