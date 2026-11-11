// CAN firewall: whitelist + per-ID rate limit with hysteresis.
// tick = one pulse per time unit (1 ms). tick and frame_valid must not coincide.
module can_firewall #(
    parameter WINDOW  = 100,  // ticks per window
    parameter LIMIT   = 12,   // max frames per ID per window
    parameter N_CLEAN = 3     // clean windows needed to release a blocked ID
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        tick,
    input  wire        frame_valid,
    input  wire [10:0] id,
    input  wire        tdoa_ok,
    output reg         decision_valid,  // one-clock pulse
    output reg         allow,
    output reg         block
);
    reg [7:0]  cnt   [0:4];
    reg [3:0]  clean [0:4];
    reg [4:0]  blocked;
    reg [15:0] wcnt;

    reg [2:0] idx;
    reg       known;
    always @* begin
        known = 1'b1;
        case (id)
            11'h0A0: idx = 3'd0;
            11'h120: idx = 3'd1;
            11'h1F0: idx = 3'd2;
            11'h2B0: idx = 3'd3;
            11'h3C0: idx = 3'd4;
            default: begin idx = 3'd0; known = 1'b0; end
        endcase
    end

    integer k;
    reg [7:0] nc;
    reg       over;

    always @(posedge clk) begin
        if (rst) begin
            for (k = 0; k < 5; k = k + 1) begin
                cnt[k] <= 8'd0;
                clean[k] <= 4'd0;
            end
            blocked <= 5'd0;
            wcnt <= 16'd0;
            decision_valid <= 1'b0;
            allow <= 1'b0;
            block <= 1'b0;
        end else begin
            decision_valid <= 1'b0;
            if (tick) begin
                if (wcnt == WINDOW - 1) begin
                    wcnt <= 16'd0;
                    for (k = 0; k < 5; k = k + 1) begin
                        if (cnt[k] > LIMIT) begin
                            blocked[k] <= 1'b1;
                            clean[k] <= 4'd0;
                        end else if (blocked[k]) begin
                            if (clean[k] + 1 >= N_CLEAN) begin
                                blocked[k] <= 1'b0;
                                clean[k] <= 4'd0;
                            end else begin
                                clean[k] <= clean[k] + 4'd1;
                            end
                        end
                        cnt[k] <= 8'd0;
                    end
                end else begin
                    wcnt <= wcnt + 16'd1;
                end
            end else if (frame_valid) begin
                decision_valid <= 1'b1;
                if (!known) begin
                    allow <= 1'b0; block <= 1'b1;
                end else begin
                    nc = (cnt[idx] == 8'hFF) ? 8'hFF : cnt[idx] + 8'd1;
                    cnt[idx] <= nc;
                    over = (nc > LIMIT);
                    if (blocked[idx] || over || !tdoa_ok) begin
                        allow <= 1'b0; block <= 1'b1;
                    end else begin
                        allow <= 1'b1; block <= 1'b0;
                    end
                end
            end
        end
    end
endmodule