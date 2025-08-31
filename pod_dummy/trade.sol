// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;


contract Trade_Escrow {
    // --------------------------
    // BN128 (alt_bn128) helpers
    // --------------------------
    struct G1Point { uint256 x; uint256 y; }

    // G1 base point for alt_bn128
    uint256 internal constant G1X = 1675371675560826509473846616033077638860463917805372242936004103743997494349; 
    uint256 internal constant G1Y = 6004808990099439655818851019291153659571390116257034679998637145356871634455; 
    function _g1() internal pure returns (G1Point memory) { return G1Point({x: G1X, y: G1Y}); }

    /// @dev Scalar-multiply a G1 point by a scalar on alt_bn128 using precompile 0x07.
    /// @param p The point to multiply (x, y)
    /// @param s The scalar
    /// @return r The resulting point r = s * p
    function _ecMul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input = [p.x, p.y, s];
        uint256[2] memory output;
        bool success;
        assembly {
            // staticcall(gas, to, in, insize, out, outsize)
            // Precompile 0x07: BN128 scalar mul, input 3*32B, output 2*32B
            success := staticcall(gas(), 0x07, input, 0x60, output, 0x40)
        }
        require(success, "ECMUL_FAIL");
        r = G1Point({x: output[0], y: output[1]});
    }

    /// @dev Compare two G1 points for equality
    function _eq(G1Point memory a, G1Point memory b) internal pure returns (bool) {
        return a.x == b.x && a.y == b.y;
    }

    // ---------------
    // Escrow storage
    // ---------------
    enum Status { None, Locked, Claimed, Refunded }

    struct Trade {
        address client;     // buyer C
        address server;     // seller S
        uint256 amount;     // wei locked
        uint256 expiry;     // unix timestamp after which client can refund
        G1Point Ys;         // server one-time public key (g1^x_s)
        uint256 xs;         // revealed scalar (optional post-claim)
        Status status;      // lifecycle
    }

    uint256 public nextTradeId;
    mapping(uint256 => Trade) public trades;

    // ---------
    // Events
    // ---------
    event Locked(uint256 indexed tradeId, address indexed client, address indexed server, uint256 amount, uint256 expiry, uint256 YsX, uint256 YsY);
    event Claimed(uint256 indexed tradeId, address indexed server, uint256 xs);
    event Refunded(uint256 indexed tradeId, address indexed client);

    // ---------
    // Errors
    // ---------
    error NotClient();
    error NotServer();
    error BadStatus(Status current);
    error NotExpired();
    error InvalidReveal();
    error ZeroValue();

    // -----------------
    // Public interface
    // -----------------

    /// @notice Client locks ETH and posts server's one-time public key Y_s = g1^{x_s}
    /// @param server The server address to receive funds upon valid reveal
    /// @param expiry Unix timestamp after which client can refund if not claimed
    /// @param YsX X coord of Y_s on alt_bn128
    /// @param YsY Y coord of Y_s on alt_bn128
    /// @return tradeId The created trade identifier
    function lock(address server, uint256 expiry, uint256 YsX, uint256 YsY) external payable returns (uint256 tradeId) {
        if (msg.value == 0) revert ZeroValue();
        tradeId = ++nextTradeId;
        trades[tradeId] = Trade({
            client: msg.sender,
            server: server,
            amount: msg.value,
            expiry: expiry,
            Ys: G1Point(YsX, YsY),
            xs: 0,
            status: Status.Locked
        });
        emit Locked(tradeId, msg.sender, server, msg.value, expiry, YsX, YsY);
    }

    /// @notice Server reveals x_s to claim funds. Requires Y_s == x_s * G
    /// @param tradeId The trade identifier
    /// @param xs The scalar private key corresponding to Y_s
    function claim(uint256 tradeId, uint256 xs) external {
        Trade storage t = trades[tradeId];
        if (t.status != Status.Locked) revert BadStatus(t.status);
        if (msg.sender != t.server) revert NotServer();

        // Verify Y_s == x_s * G
        G1Point memory computed = _ecMul(_g1(), xs);
        if (!_eq(computed, t.Ys)) revert InvalidReveal();

        t.status = Status.Claimed;
        t.xs = xs;

        // Effects-before-interactions done, now transfer
        (bool ok, ) = t.server.call{value: t.amount}("");
        require(ok, "PAY_FAIL");

        emit Claimed(tradeId, t.server, xs);
    }

    /// @notice Client refunds after expiry if the server hasn't claimed
    /// @param tradeId The trade identifier
    function refund(uint256 tradeId) external {
        Trade storage t = trades[tradeId];
        if (t.status != Status.Locked) revert BadStatus(t.status);
        if (msg.sender != t.client) revert NotClient();
        if (block.timestamp < t.expiry) revert NotExpired();

        t.status = Status.Refunded;
        (bool ok, ) = t.client.call{value: t.amount}("");
        require(ok, "REFUND_FAIL");

        emit Refunded(tradeId, t.client);
    }

    // -----------------
    // View helpers
    // -----------------

    /// @notice Convenience: recompute x_s * G and compare to stored Y_s (pure check off-chain style)
    function verifyReveal(uint256 tradeId, uint256 xs) external view returns (bool) {
        Trade storage t = trades[tradeId];
        if (t.status != Status.Locked) return false;
        G1Point memory computed = _ecMul(_g1(), xs);
        return _eq(computed, t.Ys);
    }

    /// @notice Get Y_s for a trade
    function getYs(uint256 tradeId) external view returns (uint256 x, uint256 y) {
        Trade storage t = trades[tradeId];
        return (t.Ys.x, t.Ys.y);
    }
}
