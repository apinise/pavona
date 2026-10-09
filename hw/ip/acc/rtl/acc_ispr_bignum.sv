// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

`include "prim_assert.sv"

/**
 * ISPR file for ACC WSR/CSR registers
 */

module acc_ispr_bignum
  import acc_pkg::*;
#(
  // Enabling PQC hardware support with vector ISA extension
  parameter  bit AccPQCEn = 1'b1,
  localparam int Share    = 2
) (
  input logic clk_i,
  input logic rst_ni,

  input  alu_bignum_operation_t operation_i,
  input  logic                  operation_commit_i, // used for SVAs only
  input  logic                  operation_valid_i,
  output logic                  selection_flag_o,

  input  alu_predec_bignum_t  alu_predec_bignum_i,
  input  ispr_predec_bignum_t ispr_predec_bignum_i,

  input  ispr_e                       ispr_addr_i,
  input  logic [31:0]                 ispr_base_wdata_i,
  input  logic [BaseWordsPerWLEN-1:0] ispr_base_wr_en_i,
  input  logic [ExtWLEN-1:0]          ispr_bignum_wdata_intg_i,
  input  logic                        ispr_bignum_wr_en_i,
  input  logic [NFlagGroups-1:0]      ispr_flags_wr_i,
  input  logic                        ispr_wr_commit_i,
  input  logic                        ispr_init_i,
  output logic [ExtWLEN-1:0]          ispr_rdata_intg_o,
  input  logic                        ispr_rd_en_i,

  input  logic                        kmac_intg_err_i,
  output logic                        reg_intg_violation_err_o,

  input  logic                        sec_wipe_mod_urnd_i,
  input  logic                        sec_wipe_kmac_regs_urnd_i,
  input  logic                        sec_wipe_running_i,
  output logic                        sec_wipe_err_o,

  input  logic [WLEN-1:0]             rnd_data_i,
  input  logic [WLEN-1:0]             urnd_data_i,

  input  flags_t                      mac_operation_flags_i,
  input  flags_t                      mac_operation_flags_en_i,
  input  flags_t                      alu_logic_update_flags_i,
  input  logic                        alu_logic_update_flags_en_raw_i,
  input  flags_t                      alu_adder_update_flags_i,
  input  logic                        alu_adder_update_flags_en_raw_i,
  output flags_t                      selected_flags_o,

  input  logic [ExtWLEN-1:0]          ispr_acc_intg_i,
  output logic [ExtWLEN-1:0]          ispr_acc_wr_data_intg_o,
  output logic                        ispr_acc_wr_en_o,

  input  logic [ExtWLEN-1:0]          ispr_acch_intg_i,
  output logic [ExtWLEN-1:0]          ispr_acch_wr_data_intg_o,
  output logic                        ispr_acch_wr_en_o,

  input  logic                        alu_mod_used_i,
  output logic [WLEN-1:0]             mod_no_intg_o,

  input  logic [1:0][SideloadKeyWidth-1:0] sideload_key_shares_i,

  // TODO: TMP INTG outputs to be replaced by local mux
  input  logic [31:0]             kmac_cfg_intg_i,
  input  logic [31:0]             kmac_status_intg_i,
  input  logic [ExtWLEN-1:0]      kmac_msg_intg_i    [Share],
  input  logic [ExtDigestLen-1:0] kmac_digest_intg_i [Share],

  input  logic alu_predec_error_i,
  output logic flags_predec_error_o,
  output logic ispr_predec_error_o
);

  ///////////
  // ISPRs //
  ///////////

  flags_t                              flags_d [NFlagGroups];
  flags_t                              flags_q [NFlagGroups];
  logic   [NFlagGroups*FlagsWidth-1:0] flags_flattened;
  flags_t                              selected_flags;
  flags_t                              logic_update_flags [NFlagGroups];
  flags_t                              mac_update_flags [NFlagGroups];
  logic [NFlagGroups-1:0]              mac_update_z_flag_en_blanked;
  flags_t                              ispr_update_flags [NFlagGroups];

  logic [NIspr-1:0] expected_ispr_rd_en_onehot;
  logic [NIspr-1:0] expected_ispr_wr_en_onehot;
  logic             ispr_wr_en;

  logic [NFlagGroups-1:0] expected_flag_group_sel;
  flags_t                 expected_flag_sel;
  logic [NFlagGroups-1:0] expected_flags_keep;
  logic [NFlagGroups-1:0] expected_flags_adder_update;
  logic [NFlagGroups-1:0] expected_flags_logic_update;
  logic [NFlagGroups-1:0] expected_flags_mac_update;
  logic [NFlagGroups-1:0] expected_flags_ispr_wr;

  /////////////////////
  // Flags Selection //
  /////////////////////

  always_comb begin
    expected_flag_group_sel = '0;
    expected_flag_group_sel[operation_i.flag_group] = 1'b1;
  end
  assign expected_flag_sel.C = operation_i.sel_flag == FlagC;
  assign expected_flag_sel.M = operation_i.sel_flag == FlagM;
  assign expected_flag_sel.L = operation_i.sel_flag == FlagL;
  assign expected_flag_sel.Z = operation_i.sel_flag == FlagZ;

  // SEC_CM: DATA_REG_SW.SCA
  prim_onehot_mux #(
    .Width(FlagsWidth),
    .Inputs(NFlagGroups)
  ) u_flags_q_mux (
    .clk_i,
    .rst_ni,
    .in_i  (flags_q),
    .sel_i (alu_predec_bignum_i.flag_group_sel),
    .out_o (selected_flags)
  );

  assign selected_flags_o = selected_flags;

  // If flag_group_t is fully populated and flag_e covers all encodings this won't be reachable
  `ASSERT(BlankingSelectedFlags_A, expected_flag_group_sel == '0 |-> selected_flags == '0, clk_i,
    !rst_ni || alu_predec_error_i || flags_predec_error_o || !operation_commit_i)


  logic                  flag_mux_in [FlagsWidth];
  logic [FlagsWidth-1:0] flag_mux_sel;
  assign flag_mux_in = '{selected_flags.C,
                         selected_flags.M,
                         selected_flags.L,
                         selected_flags.Z};
  assign flag_mux_sel = {alu_predec_bignum_i.flag_sel.Z,
                         alu_predec_bignum_i.flag_sel.L,
                         alu_predec_bignum_i.flag_sel.M,
                         alu_predec_bignum_i.flag_sel.C};

  // SEC_CM: DATA_REG_SW.SCA
  prim_onehot_mux #(
    .Width(1),
    .Inputs(FlagsWidth)
  ) u_flag_mux (
    .clk_i,
    .rst_ni,
    .in_i  (flag_mux_in),
    .sel_i (flag_mux_sel),
    .out_o (selection_flag_o)
  );

  // If flag_group_t is fully populated and flag_e covers all encodings this won't be reachable
  `ASSERT(BlankingSelectionFlag_A, expected_flag_sel == '0 |-> selection_flag_o == '0, clk_i,
    !rst_ni || alu_predec_error_i  || flags_predec_error_o || !operation_commit_i)

  //////////////////
  // Flags Update //
  //////////////////

  // Note that the flag zeroing triggred by ispr_init_i and secure wipe is achieved by not
  // selecting any inputs in the one-hot muxes below. The instruction fetch/predecoder stage
  // is driving the selector inputs accordingly.

  always_comb begin
    expected_flags_adder_update = '0;
    expected_flags_logic_update = '0;
    expected_flags_mac_update   = '0;

    expected_flags_adder_update[operation_i.flag_group] = operation_i.alu_flag_en &
                                                          alu_adder_update_flags_en_raw_i;
    expected_flags_logic_update[operation_i.flag_group] = operation_i.alu_flag_en &
                                                          alu_logic_update_flags_en_raw_i;
    expected_flags_mac_update[operation_i.flag_group]   = operation_i.mac_flag_en;
  end
  assign expected_flags_ispr_wr = ispr_flags_wr_i;

  assign expected_flags_keep = ~(expected_flags_adder_update |
                                 expected_flags_logic_update |
                                 expected_flags_mac_update |
                                 expected_flags_ispr_wr);

  // Tie off unused signals.
  logic unused_logic_update_flags;
  assign unused_logic_update_flags = alu_logic_update_flags_i.C;
  logic unused_mac_operation_flags;
  assign unused_mac_operation_flags = mac_operation_flags_i.C ^ mac_operation_flags_en_i.C;

  for (genvar i_fg = 0; i_fg < NFlagGroups; i_fg++) begin : g_update_flag_groups

    /////////////////
    // Logic Flags //
    /////////////////

    // Logical operations only update M, L and Z; C must remain at its old value.
    assign logic_update_flags[i_fg].C = flags_q[i_fg].C;
    assign logic_update_flags[i_fg].M = alu_logic_update_flags_i.M;
    assign logic_update_flags[i_fg].L = alu_logic_update_flags_i.L;
    assign logic_update_flags[i_fg].Z = alu_logic_update_flags_i.Z;

    ///////////////
    // MAC Flags //
    ///////////////

    // MAC operations don't update C.
    assign mac_update_flags[i_fg].C = flags_q[i_fg].C;

    // MAC operations update M and L depending on the operation. The individual enable signals for
    // M and L are generated from flopped instruction bits with minimal logic. They are not data
    // dependent.
    assign mac_update_flags[i_fg].M = mac_operation_flags_en_i.M ?
                                      mac_operation_flags_i.M : flags_q[i_fg].M;
    assign mac_update_flags[i_fg].L = mac_operation_flags_en_i.L ?
                                      mac_operation_flags_i.L : flags_q[i_fg].L;

    // MAC operations update Z depending on the operation and data. For BN.MULQACC.SO, already the
    // enable signal is data dependent (it depends on the lower half of the accumulator result). As
    // a result the enable signal might change back and forth during instruction execution which may
    // lead to SCA leakage. There is nothing that can really be done to avoid this other than
    // pipelining the flag computation which has a performance impact.
    //
    // By blanking the enable signal for the other flag group, we can at least avoid leakage related
    // to the other flag group, i.e., we give the programmer a way to control where the leakage
    // happens.
    // SEC_CM: DATA_REG_SW.SCA
    prim_blanker #(.Width(1)) u_mac_z_flag_en_blanker (
      .in_i (mac_operation_flags_en_i.Z),
      .en_i (alu_predec_bignum_i.flags_mac_update[i_fg]),
      .out_o(mac_update_z_flag_en_blanked[i_fg])
    );
    assign mac_update_flags[i_fg].Z = mac_update_z_flag_en_blanked[i_fg] ?
                                      mac_operation_flags_i.Z : flags_q[i_fg].Z;

    // For ISPR writes, we get the full write data from the base ALU and will select the relevant
    // parts using the blankers and one-hot muxes below.
    assign ispr_update_flags[i_fg] = ispr_base_wdata_i[i_fg*FlagsWidth+:FlagsWidth];
  end

  localparam int NFlagsSrcs = 5;
  for (genvar i_fg = 0; i_fg < NFlagGroups; i_fg++) begin : g_flag_groups

    flags_t                flags_d_mux_in [NFlagsSrcs];
    logic [NFlagsSrcs-1:0] flags_d_mux_sel;
    assign flags_d_mux_in = '{ispr_update_flags[i_fg],
                              mac_update_flags[i_fg],
                              logic_update_flags[i_fg],
                              alu_adder_update_flags_i,
                              flags_q[i_fg]};
    assign flags_d_mux_sel = {alu_predec_bignum_i.flags_keep[i_fg],
                              alu_predec_bignum_i.flags_adder_update[i_fg],
                              alu_predec_bignum_i.flags_logic_update[i_fg],
                              alu_predec_bignum_i.flags_mac_update[i_fg],
                              alu_predec_bignum_i.flags_ispr_wr[i_fg]};

    // SEC_CM: DATA_REG_SW.SCA
    prim_onehot_mux #(
      .Width(FlagsWidth),
      .Inputs(NFlagsSrcs)
    ) u_flags_d_mux (
      .clk_i,
      .rst_ni,
      .in_i  (flags_d_mux_in),
      .sel_i (flags_d_mux_sel),
      .out_o (flags_d[i_fg])
    );

    always_ff @(posedge clk_i or negedge rst_ni) begin
      if (!rst_ni) begin
        flags_q[i_fg] <= '{Z : 1'b0, L : 1'b0, M : 1'b0, C : 1'b0};
      end else begin
        flags_q[i_fg] <= flags_d[i_fg];
      end
    end

    assign flags_flattened[i_fg*FlagsWidth+:FlagsWidth] = flags_q[i_fg];
  end

  assign flags_predec_error_o =
    |{expected_flag_group_sel != alu_predec_bignum_i.flag_group_sel,
      expected_flag_sel != alu_predec_bignum_i.flag_sel,
      expected_flags_keep != alu_predec_bignum_i.flags_keep,
      expected_flags_adder_update != alu_predec_bignum_i.flags_adder_update,
      expected_flags_logic_update != alu_predec_bignum_i.flags_logic_update,
      expected_flags_mac_update != alu_predec_bignum_i.flags_mac_update,
      expected_flags_ispr_wr != alu_predec_bignum_i.flags_ispr_wr};

  /////////
  // MOD //
  /////////

  logic [ExtWLEN-1:0]          mod_intg_q;
  logic [ExtWLEN-1:0]          mod_intg_d;
  logic [BaseWordsPerWLEN-1:0] mod_ispr_wr_en;
  logic [BaseWordsPerWLEN-1:0] mod_wr_en;

  logic [ExtWLEN-1:0] ispr_mod_bignum_wdata_intg_blanked;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(ExtWLEN)) u_ispr_mod_bignum_wdata_blanker (
    .in_i (ispr_bignum_wdata_intg_i),
    .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprMod]),
    .out_o(ispr_mod_bignum_wdata_intg_blanked)
  );
  // If the blanker is enabled, the output will not carry the correct ECC bits.  This is not
  // a problem because a blanked value should never be written to the register.  If the blanked
  // value is written to the register nonetheless, an integrity error arises.

  logic [WLEN-1:0]                mod_no_intg_d;
  logic [WLEN-1:0]                mod_no_intg_q;
  logic [ExtWLEN-1:0]             mod_intg_calc;
  logic [2*BaseWordsPerWLEN-1:0]  mod_intg_err;
  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_mod_words
    prim_secded_inv_39_32_enc i_secded_enc (
      .data_i (mod_no_intg_d[i_word*32+:32]),
      .data_o (mod_intg_calc[i_word*39+:39])
    );
    prim_secded_inv_39_32_dec i_secded_dec (
      .data_i     (mod_intg_q[i_word*39+:39]),
      .data_o     (/* unused because we abort on any integrity error */),
      .syndrome_o (/* unused */),
      .err_o      (mod_intg_err[i_word*2+:2])
    );
    assign mod_no_intg_q[i_word*32+:32] = mod_intg_q[i_word*39+:32];

    always_ff @(posedge clk_i) begin
      if (mod_wr_en[i_word]) begin
        mod_intg_q[i_word*39+:39] <= mod_intg_d[i_word*39+:39];
      end
    end

    always_comb begin
      mod_no_intg_d[i_word*32+:32] = '0;
      unique case (1'b1)
        // Non-encoded inputs have to be encoded before writing to the register.
        sec_wipe_mod_urnd_i: begin
          // In a secure wipe, `urnd_data_i` is written to the register before the zero word.  The
          // ECC bits should not matter between the two writes, but nonetheless we encode
          // `urnd_data_i` so there is no spurious integrity error.
          mod_no_intg_d[i_word*32+:32] = urnd_data_i[i_word*32+:32];
          mod_intg_d[i_word*39+:39]  = mod_intg_calc[i_word*39+:39];
        end
        // Pre-encoded inputs can directly be written to the register.
        default: mod_intg_d[i_word*39+:39] = ispr_mod_bignum_wdata_intg_blanked[i_word*39+:39];
      endcase

      unique case (1'b1)
        ispr_init_i: mod_intg_d[i_word*39+:39] = EccZeroWord;
        ispr_base_wr_en_i[i_word]: begin
          mod_no_intg_d[i_word*32+:32] = ispr_base_wdata_i;
          mod_intg_d[i_word*39+:39] = mod_intg_calc[i_word*39+:39];
        end
        default: ;
      endcase
    end

    `ASSERT(ModWrSelOneHot, $onehot0({ispr_init_i, ispr_base_wr_en_i[i_word]}))

    assign mod_ispr_wr_en[i_word] = (ispr_addr_i == IsprMod)                          &
                                    (ispr_base_wr_en_i[i_word] | ispr_bignum_wr_en_i) &
                                    ispr_wr_commit_i;

    assign mod_wr_en[i_word] = ispr_init_i            |
                               mod_ispr_wr_en[i_word] |
                               sec_wipe_mod_urnd_i;
  end

  assign mod_no_intg_o = mod_no_intg_q;

  /////////
  // ACC //
  /////////

  assign ispr_acc_wr_en_o   =
    ((ispr_addr_i == IsprAcc) & ispr_bignum_wr_en_i & ispr_wr_commit_i) | ispr_init_i;


  logic [ExtWLEN-1:0] ispr_acc_bignum_wdata_intg_blanked;

  // SEC_CM: DATA_REG_SW.SCA
  prim_blanker #(.Width(ExtWLEN)) u_ispr_acc_bignum_wdata_intg_blanker (
    .in_i (ispr_bignum_wdata_intg_i),
    .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprAcc]),
    .out_o(ispr_acc_bignum_wdata_intg_blanked)
  );
  // If the blanker is enabled, the output will not carry the correct ECC bits.  This is not
  // a problem because a blanked value should never be used.  If the blanked value is used
  // nonetheless, an integrity error arises.

  assign ispr_acc_wr_data_intg_o = ispr_init_i ? EccWideZeroWord
                                               : ispr_acc_bignum_wdata_intg_blanked;

  //////////
  // ACCH //
  //////////
  generate
    if (AccPQCEn) begin : gen_acch_wsr
      assign ispr_acch_wr_en_o =
          ((ispr_addr_i == IsprAccH) & ispr_bignum_wr_en_i & ispr_wr_commit_i) | ispr_init_i;

      logic [ExtWLEN-1:0] ispr_acch_bignum_wdata_intg_blanked;

      // SEC_CM: DATA_REG_SW.SCA
      prim_blanker #(.Width(ExtWLEN)) u_ispr_acch_bignum_wdata_intg_blanker (
        .in_i (ispr_bignum_wdata_intg_i),
        .en_i (ispr_predec_bignum_i.ispr_wr_en[IsprAccH]),
        .out_o(ispr_acch_bignum_wdata_intg_blanked)
      );
      // If the blanker is enabled, the output will not carry the correct ECC bits.  This is not
      // a problem because a blanked value should never be used.  If the blanked value is used
      // nonetheless, an integrity error arises.

      assign ispr_acch_wr_data_intg_o = ispr_init_i ? EccWideZeroWord
                                                  : ispr_acch_bignum_wdata_intg_blanked;

      // ACCH ISPR Blanking
      `ASSERT(BlankingIsprACCH_A,
              !(|ispr_acch_wr_en_o) |-> ispr_acch_bignum_wdata_intg_blanked == '0,
              clk_i, !rst_ni || ispr_predec_error_o || flags_predec_error_o ||
                                alu_predec_error_i  || !operation_commit_i)
    end else begin : gen_acch_tieoff
      assign ispr_acch_wr_en_o        = '0;
      assign ispr_acch_wr_data_intg_o = '0;
    end
  endgenerate

  //////////////
  // READ MUX //
  //////////////

  // ISPR read data is muxed out in two stages:
  // 1. Select amongst the ISPRs that have no integrity bits. The output has integrity calculated
  //    for it.
  // 2. Select between the ISPRs that have integrity bits and the result of the first stage.

  // IDs fpr ISPRs with integrity
  localparam int IsprModIntg        = 0;
  localparam int IsprAccIntg        = 1;
  generate
    if (AccPQCEn) begin : gen_ispr_ids_pqc
      localparam int IsprKmacMsg0Intg    = 2;
      localparam int IsprKmacMsg1Intg    = 3;
      localparam int IsprKmacDigest0Intg = 4;
      localparam int IsprKmacDigest1Intg = 5;
      localparam int IsprAccHIntg        = 6;
    end
  endgenerate

  // ID representing all ISPRs with no integrity
  localparam int IsprNoIntg = AccPQCEn ? 7 : 2;
  // Number of ISPRs that have integrity protection
  localparam int NIntgIspr  = AccPQCEn ? 7 : 2;

  logic [NIntgIspr:0] ispr_rdata_intg_mux_sel;
  logic [ExtWLEN-1:0] ispr_rdata_intg_mux_in    [NIntgIspr+1];
  logic [WLEN-1:0]    ispr_rdata_no_intg_mux_in [NIspr];

  // First stage
  // MOD, ACC, KMAC_MSG and KMAC_DIGEST supply their own integrity so these values are unused
  assign ispr_rdata_no_intg_mux_in[IsprMod]         = 0;
  assign ispr_rdata_no_intg_mux_in[IsprAcc]         = 0;
  generate
    if (AccPQCEn) begin : gen_ispr_no_intg_mux_pqc
      assign ispr_rdata_no_intg_mux_in[IsprKmacMsg0] = 0;
      assign ispr_rdata_no_intg_mux_in[IsprKmacMsg1] = 0;

      assign ispr_rdata_no_intg_mux_in[IsprKmacCfg] =
          {224'b0, kmac_cfg_intg_i};

      assign ispr_rdata_no_intg_mux_in[IsprKmacStatus] =
          {224'b0, kmac_status_intg_i};

      assign ispr_rdata_no_intg_mux_in[IsprKmacDigest0] = 0;
      assign ispr_rdata_no_intg_mux_in[IsprKmacDigest1] = 0;
      assign ispr_rdata_no_intg_mux_in[IsprAccH]        = 0;
    end
  endgenerate

  assign ispr_rdata_no_intg_mux_in[IsprRnd]    = rnd_data_i;
  assign ispr_rdata_no_intg_mux_in[IsprUrnd]   = urnd_data_i;
  assign ispr_rdata_no_intg_mux_in[IsprFlags]  = {{(WLEN - (NFlagGroups * FlagsWidth)){1'b0}},
                                                flags_flattened};
  // SEC_CM: KEY.SIDELOAD
  assign ispr_rdata_no_intg_mux_in[IsprKeyS0L] = sideload_key_shares_i[0][255:0];
  assign ispr_rdata_no_intg_mux_in[IsprKeyS0H] = {{(WLEN - (SideloadKeyWidth - 256)){1'b0}},
                                                 sideload_key_shares_i[0][SideloadKeyWidth-1:256]};
  assign ispr_rdata_no_intg_mux_in[IsprKeyS1L] = sideload_key_shares_i[1][255:0];
  assign ispr_rdata_no_intg_mux_in[IsprKeyS1H] = {{(WLEN - (SideloadKeyWidth - 256)){1'b0}},
                                                 sideload_key_shares_i[1][SideloadKeyWidth-1:256]};

  logic [WLEN-1:0]    ispr_rdata_no_intg;
  logic [ExtWLEN-1:0] ispr_rdata_intg_calc;

  // SEC_CM: DATA_REG_SW.SCA
  prim_onehot_mux #(
    .Width  (WLEN),
    .Inputs (NIspr)
  ) u_ispr_rdata_no_intg_mux (
    .clk_i,
    .rst_ni,
    .in_i  (ispr_rdata_no_intg_mux_in),
    .sel_i (ispr_predec_bignum_i.ispr_rd_en),
    .out_o (ispr_rdata_no_intg)
  );

  for (genvar i_word = 0; i_word < BaseWordsPerWLEN; i_word++) begin : g_rdata_enc
    prim_secded_inv_39_32_enc i_secded_enc (
      .data_i(ispr_rdata_no_intg[i_word * 32 +: 32]),
      .data_o(ispr_rdata_intg_calc[i_word * 39 +: 39])
    );
  end

  // Second stage
  assign ispr_rdata_intg_mux_in[IsprModIntg] = mod_intg_q;
  assign ispr_rdata_intg_mux_in[IsprAccIntg] = ispr_acc_intg_i;
  assign ispr_rdata_intg_mux_in[IsprNoIntg]  = ispr_rdata_intg_calc;

  generate
    if (AccPQCEn) begin : gen_ispr_intg_mux_pqc
      assign ispr_rdata_intg_mux_in[gen_ispr_ids_pqc.IsprKmacMsg0Intg]    =
          kmac_msg_intg_i[0];
      assign ispr_rdata_intg_mux_in[gen_ispr_ids_pqc.IsprKmacMsg1Intg]    =
          kmac_msg_intg_i[1];
      assign ispr_rdata_intg_mux_in[gen_ispr_ids_pqc.IsprKmacDigest0Intg] =
          kmac_digest_intg_i[0];
      assign ispr_rdata_intg_mux_in[gen_ispr_ids_pqc.IsprKmacDigest1Intg] =
          kmac_digest_intg_i[1];
      assign ispr_rdata_intg_mux_in[gen_ispr_ids_pqc.IsprAccHIntg]        = ispr_acch_intg_i;
    end
  endgenerate

  assign ispr_rdata_intg_mux_sel[IsprModIntg] = ispr_predec_bignum_i.ispr_rd_en[IsprMod];
  assign ispr_rdata_intg_mux_sel[IsprAccIntg] = ispr_predec_bignum_i.ispr_rd_en[IsprAcc];

  generate
    if (AccPQCEn) begin : gen_ispr_intg_mux_sel_pqc
      assign ispr_rdata_intg_mux_sel[gen_ispr_ids_pqc.IsprKmacMsg0Intg]     =
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacMsg0];
      assign ispr_rdata_intg_mux_sel[gen_ispr_ids_pqc.IsprKmacMsg1Intg]     =
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacMsg1];
      assign ispr_rdata_intg_mux_sel[gen_ispr_ids_pqc.IsprKmacDigest0Intg] =
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest0];
      assign ispr_rdata_intg_mux_sel[gen_ispr_ids_pqc.IsprKmacDigest1Intg] =
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1];
      assign ispr_rdata_intg_mux_sel[gen_ispr_ids_pqc.IsprAccHIntg]        =
          ispr_predec_bignum_i.ispr_rd_en[IsprAccH];
    end
  endgenerate

  generate
    if (AccPQCEn) begin : gen_ispr_intg_mux_sel_cat_pqc
      assign ispr_rdata_intg_mux_sel[IsprNoIntg]  =
        |{ispr_predec_bignum_i.ispr_rd_en[IsprKeyS1H:IsprKeyS0L],
          ispr_predec_bignum_i.ispr_rd_en[IsprUrnd],
          ispr_predec_bignum_i.ispr_rd_en[IsprFlags],
          ispr_predec_bignum_i.ispr_rd_en[IsprRnd],
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacCfg],
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacPartialW],
          ispr_predec_bignum_i.ispr_rd_en[IsprKmacStatus]};
    end else begin : gen_ispr_intg_mux_sel_cat
      assign ispr_rdata_intg_mux_sel[IsprNoIntg]  =
        |{ispr_predec_bignum_i.ispr_rd_en[IsprKeyS1H:IsprKeyS0L],
          ispr_predec_bignum_i.ispr_rd_en[IsprUrnd],
          ispr_predec_bignum_i.ispr_rd_en[IsprFlags],
          ispr_predec_bignum_i.ispr_rd_en[IsprRnd]};
    end
  endgenerate

  // If we're reading from an ISPR we must be using the ispr_rdata_intg_mux
  `ASSERT(IsprRDataIntgMuxSelIfIsprRd_A,
    |ispr_predec_bignum_i.ispr_rd_en |-> |ispr_rdata_intg_mux_sel)

  // If we're reading from MOD or ACC we must not take the read data from the calculated integrity
  // path
  `ASSERT(IsprModMustTakeIntg_A,
    ispr_predec_bignum_i.ispr_rd_en[IsprMod] |-> !ispr_rdata_intg_mux_sel[IsprNoIntg])

  `ASSERT(IsprAccMustTakeIntg_A,
    ispr_predec_bignum_i.ispr_rd_en[IsprAcc] |-> !ispr_rdata_intg_mux_sel[IsprNoIntg])

  generate
    if (AccPQCEn) begin : gen_acch_intg_assert
      `ASSERT(IsprAccHMustTakeIntg_A,
        ispr_predec_bignum_i.ispr_rd_en[IsprAccH] |-> !ispr_rdata_intg_mux_sel[IsprNoIntg])
    end
  endgenerate

  prim_onehot_mux #(
    .Width  (ExtWLEN),
    .Inputs (NIntgIspr+1)
  ) u_ispr_rdata_intg_mux (
    .clk_i,
    .rst_ni,
    .in_i  (ispr_rdata_intg_mux_in),
    .sel_i (ispr_rdata_intg_mux_sel),
    .out_o (ispr_rdata_intg_o)
  );

  prim_onehot_enc #(
    .OneHotWidth (NIspr)
  ) u_expected_ispr_rd_en_enc (
    .in_i(ispr_addr_i),
    .en_i (ispr_rd_en_i),
    .out_o (expected_ispr_rd_en_onehot)
  );

  assign ispr_wr_en = |{ispr_bignum_wr_en_i, ispr_base_wr_en_i};

  prim_onehot_enc #(
    .OneHotWidth (NIspr)
  ) u_expected_ispr_wr_en_enc (
    .in_i(ispr_addr_i),
    .en_i (ispr_wr_en),
    .out_o (expected_ispr_wr_en_onehot)
  );

  // SEC_CM: CTRL.REDUN
  assign ispr_predec_error_o =
    |{expected_ispr_rd_en_onehot != ispr_predec_bignum_i.ispr_rd_en,
      expected_ispr_wr_en_onehot != ispr_predec_bignum_i.ispr_wr_en};

  // Tie off unused signals.
  logic unused_operation_commit;
  assign unused_operation_commit = operation_commit_i;

  //////////////////
  // REG INTG ERR //
  //////////////////

  generate
    if (AccPQCEn) begin : gen_reg_intg_err_pqc
      logic kmac_used;
      assign kmac_used = operation_valid_i & (operation_i.op != AluOpBignumNone) &
                         ( |(ispr_predec_bignum_i.ispr_rd_en[IsprKmacMsg0])    |
                           |(ispr_predec_bignum_i.ispr_rd_en[IsprKmacMsg1])    |
                           |(ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest0]) |
                           |(ispr_predec_bignum_i.ispr_rd_en[IsprKmacDigest1]) |
                           |(ispr_predec_bignum_i.ispr_rd_en[IsprKmacCfg])     |
                           |(ispr_predec_bignum_i.ispr_rd_en[IsprKmacStatus])  );
      `ASSERT_KNOWN(KmacUsed_A, kmac_used)

      // Raise a register integrity violation error iff `mod_intg_q` is used
      // and (at least partially) invalid.
      assign reg_intg_violation_err_o = (alu_mod_used_i & |(mod_intg_err)) |
                                        (kmac_used & kmac_intg_err_i);

      // Detect and signal unexpected secure wipe signals.
      assign sec_wipe_err_o = (sec_wipe_kmac_regs_urnd_i | sec_wipe_mod_urnd_i)
                              & ~sec_wipe_running_i;
    end else begin : gen_reg_intg_err
      // Raise a register integrity violation error iff `mod_intg_q` is used
      // and (at least partially)invalid.
      assign reg_intg_violation_err_o = alu_mod_used_i & |(mod_intg_err);

      // Detect and signal unexpected secure wipe signals.
      assign sec_wipe_err_o = sec_wipe_mod_urnd_i & ~sec_wipe_running_i;
    end
  endgenerate

  `ASSERT_KNOWN(RegIntgErrKnown_A, reg_intg_violation_err_o)

  ////////////////
  // ASSERTIONS //
  ////////////////

  // ACC ISPR Blanking
  `ASSERT(BlankingIsprACC_A,
          !(|ispr_acc_wr_en_o) |-> ispr_acc_bignum_wdata_intg_blanked == '0,
          clk_i, !rst_ni || ispr_predec_error_o || flags_predec_error_o ||
                            alu_predec_error_i  || !operation_commit_i)

  // ACCH is inside the ACCH WSR generate block

  // MOD ISPR Blanking
  `ASSERT(BlankingIsprMod_A,
          !(|mod_wr_en) |-> ispr_mod_bignum_wdata_intg_blanked == '0,
          clk_i, !rst_ni || ispr_predec_error_o || flags_predec_error_o ||
                            alu_predec_error_i  || !operation_commit_i)

endmodule