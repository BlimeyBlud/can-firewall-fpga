`timescale 1ns/1ps
`include "params.vh"

module tb_can_parser;
    reg clk = 0, rst = 1, rx_bit = 1;
    wire [10:0] id;
    wire [3:0]  dlc;
    wire [63:0] data;
    wire        frame_valid;

    can_parser dut (.clk(clk), .rst(rst), .rx_bit(rx_bit),
                    .id(id), .dlc(dlc), .data(data), .frame_valid(frame_valid));

    always #5 clk = ~clk;

    reg [0:0]  bits     [0:`NBITS-1];
    reg [79:0] expected [0:`NFRAMES-1];
    integer i;
    integer nframe = 0;
    integer errors = 0;

    // Checker: compare every frame_valid pulse to the answer key
    always @(posedge clk) begin
        if (frame_valid) begin
            if (nframe < `NFRAMES) begin
                if ({1'b0, id, dlc, data} !== expected[nframe]) begin
                    errors = errors + 1;
                    $display("MISMATCH frame %0d: got %h expected %h",
                             nframe, {1'b0, id, dlc, data}, expected[nframe]);
                end
            end else begin
                errors = errors + 1;
                $display("EXTRA frame %0d", nframe);
            end
            nframe = nframe + 1;
        end
    end

    initial begin
        $readmemh("tb/frames.hex", bits);
        $readmemh("tb/expected.txt", expected);
        $dumpfile("tb/parser.vcd");
        $dumpvars(0, tb_can_parser);

        repeat (4) @(posedge clk);
        rst <= 0;
        for (i = 0; i < `NBITS; i = i + 1) begin
            @(posedge clk);
            rx_bit <= bits[i];
        end
        repeat (20) @(posedge clk);

        $display("Frames received: %0d / %0d, errors: %0d", nframe, `NFRAMES, errors);
        if (nframe == `NFRAMES && errors == 0) $display("PASS");
        else $display("FAIL");
        $finish;
    end
endmodule