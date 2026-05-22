// Copyright lowRISC contributors (OpenTitan project).
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Bound into the acc_mac_bignum and used to help collect ISPR information for coverage.

interface acc_mac_bignum_if #(
  // Enabling PQC hardware support with vector ISA extension
  parameter bit AccPQCEn = acc_pqc_env_pkg::AccPQCEn,
  localparam int WLEN = AccPQCEn ? 512 : 256
) (
  input         clk_i,
  input         rst_ni,

  // Signal names from the acc_mac_bignum module (where we are bound)
  input logic [WLEN-1:0]              adder_op_a,
  input logic [WLEN-1:0]              adder_op_b
);

  // Return the intermediate sum (the value of ACC before it gets truncated back down to 256 bits).
  function automatic logic [WLEN:0] get_sum_value();
    return {1'b0, adder_op_a} + {1'b0, adder_op_b};
  endfunction

endinterface
