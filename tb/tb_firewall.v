`timescale 1ns/1ps
`include "fw_params.vh"

module tb_firewall;
    reg clk = 0, rst = 1, tick = 0, frame_valid = 0, tdoa_ok = 1;
    reg [10:0] id = 0;
    wire decision_valid, allow, block;

    can_firewall dut (.clk(clk), .rst(rst), .tick(tick), .frame_valid(frame_valid),
                      .id(id), .tdoa_ok(tdoa_ok),
                      .decision_valid(decision_valid), .allow(allow), .block(block));

    always #5 clk = ~clk;

    reg [15:0] ev   [0:`NEV-1];
    reg [0:0]  want [0:`NFR-1];
    integer i;
    integer nd = 0, errors = 0, nblocked = 0;

    always @(posedge clk) begin
        if (decision_valid) begin
            if (nd < `NFR) begin
                if (allow !== want[nd]) begin
                    errors = errors + 1;
                    if (errors <= 5) $display("MISMATCH frame %0d: got allow=%b expected %b", nd, allow, want[nd]);
                end
            end
            if (block) nblocked = nblocked + 1;
            nd = nd + 1;
        end
    end

    initial begin
        $readmemh("tb/fw_in.txt", ev);
        $readmemh("tb/fw_exp.txt", want);
        $dumpfile("tb/firewall.vcd");
        $dumpvars(0, tb_firewall);

        repeat (4) @(posedge clk);
        rst <= 0;
        for (i = 0; i < `NEV; i = i + 1) begin
            @(posedge clk);
            if (ev[i][15]) begin
                tick <= 1; frame_valid <= 0;
            end else begin
                tick <= 0; frame_valid <= 1; id <= ev[i][10:0];
            end
            @(posedge clk);
            tick <= 0; frame_valid <= 0;
        end
        repeat (5) @(posedge clk);

        $display("Frames decided: %0d / %0d, blocked: %0d, errors: %0d", nd, `NFR, nblocked, errors);
        if (nd == `NFR && errors == 0) $display("PASS");
        else $display("FAIL");
        $finish;
    end
endmodule