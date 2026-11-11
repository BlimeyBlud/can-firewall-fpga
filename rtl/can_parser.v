// CAN 2.0A frame parser: 1 bit per clock, destuffs, extracts ID/DLC/data.
module can_parser (
    input  wire        clk,
    input  wire        rst,
    input  wire        rx_bit,
    output reg  [10:0] id,
    output reg  [3:0]  dlc,
    output reg  [63:0] data,        // first data byte in the top bits
    output reg         frame_valid  // one-clock pulse, outputs valid at that time
);
    localparam S_IDLE = 2'd0, S_HDR = 2'd1, S_DATA = 2'd2, S_WAIT = 2'd3;

    reg [1:0]  state;
    reg        last;     // previous destuff bit
    reg [2:0]  run;      // length of current run of identical bits
    reg [4:0]  cnt;      // header bits received (after SOF)
    reg [17:0] hdr;      // ID(11) RTR IDE r0 DLC(4)
    reg [6:0]  dcnt;     // data bits received
    reg [6:0]  ntot;     // total data bits expected
    reg [3:0]  ones;     // consecutive recessive bits while waiting for idle

    wire        is_stuff  = (run == 3'd5);          // this bit is a stuff bit: drop it
    wire [17:0] hdr_full  = {hdr[16:0], rx_bit};
    wire [3:0]  dlc_full  = hdr_full[3:0];
    wire [6:0]  ntot_full = (dlc_full > 4'd8) ? 7'd64 : {dlc_full, 3'b000};

    always @(posedge clk) begin
        if (rst) begin
            state <= S_WAIT; ones <= 4'd0;
            last <= 1'b1; run <= 3'd0; cnt <= 5'd0; hdr <= 18'd0;
            dcnt <= 7'd0; ntot <= 7'd0;
            id <= 11'd0; dlc <= 4'd0; data <= 64'd0; frame_valid <= 1'b0;
        end else begin
            frame_valid <= 1'b0;
            case (state)
                S_IDLE: begin
                    if (!rx_bit) begin           // SOF = dominant bit after idle
                        state <= S_HDR;
                        last <= 1'b0; run <= 3'd1;
                        cnt <= 5'd0; hdr <= 18'd0; data <= 64'd0;
                    end
                end

                S_HDR: begin
                    if (is_stuff) begin
                        last <= rx_bit; run <= 3'd1;
                    end else begin
                        if (rx_bit == last) run <= run + 3'd1;
                        else begin last <= rx_bit; run <= 3'd1; end
                        hdr <= hdr_full;
                        cnt <= cnt + 5'd1;
                        if (cnt == 5'd17) begin  // last DLC bit just arrived
                            id   <= hdr_full[17:7];
                            dlc  <= dlc_full;
                            ntot <= ntot_full;
                            dcnt <= 7'd0;
                            if (ntot_full == 7'd0) begin
                                frame_valid <= 1'b1;
                                state <= S_WAIT; ones <= 4'd0;
                            end else begin
                                state <= S_DATA;
                            end
                        end
                    end
                end

                S_DATA: begin
                    if (is_stuff) begin
                        last <= rx_bit; run <= 3'd1;
                    end else begin
                        if (rx_bit == last) run <= run + 3'd1;
                        else begin last <= rx_bit; run <= 3'd1; end
                        data[63 - dcnt] <= rx_bit;
                        dcnt <= dcnt + 7'd1;
                        if (dcnt == ntot - 7'd1) begin
                            frame_valid <= 1'b1;
                            state <= S_WAIT; ones <= 4'd0;
                        end
                    end
                end

                S_WAIT: begin                    // skip CRC/ACK/EOF: wait for 8 ones in a row
                    if (rx_bit) begin
                        if (ones >= 4'd7) state <= S_IDLE;
                        else ones <= ones + 4'd1;
                    end else begin
                        ones <= 4'd0;
                    end
                end
            endcase
        end
    end
endmodule