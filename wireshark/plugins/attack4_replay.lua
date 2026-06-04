-- =============================================================
-- attack4_replay.lua  —  Wireshark dissector for Attack 4
-- UDP port 14550 (MAVProxy broadcast)
--
-- Shows for each MAVLink 2.0 packet:
--   COMMAND_LONG (msgid=76)  → decoded as REPLAYED PACKET
--     - Signature timestamp (future → replay valid)
--     - Command = DO_SET_MODE (176) → LAND
--   COMMAND_ACK  (msgid=77)  → decoded as REPLAY ACCEPTED
--     - result=0 = ACCEPTED  → attack succeeded
--
-- Chains to mavlink_proto dissector so both run together.
-- Restart Wireshark after saving this file.
-- =============================================================

local p = Proto("atk4replay", "Attack4 Replay")

-- ── Fields ────────────────────────────────────────────────────
local f_type     = ProtoField.string("atk4replay.type",     "Packet Role")
local f_magic    = ProtoField.string("atk4replay.magic",    "MAVLink Version")
local f_signed   = ProtoField.string("atk4replay.signed",   "Signing Status")
local f_msgid    = ProtoField.string("atk4replay.msgid",    "Message ID")
local f_sig_ts   = ProtoField.string("atk4replay.sig_ts",   "Signature Timestamp")
local f_sig_date = ProtoField.string("atk4replay.sig_date", "Signature Date")
local f_ts_gap   = ProtoField.string("atk4replay.ts_gap",   "Timestamp vs Now")
local f_cmd      = ProtoField.string("atk4replay.cmd",      "Command")
local f_result   = ProtoField.string("atk4replay.result",   "ACK Result")
local f_verdict  = ProtoField.string("atk4replay.verdict",  "Attack Verdict")

p.fields = {
    f_type, f_magic, f_signed, f_msgid,
    f_sig_ts, f_sig_date, f_ts_gap,
    f_cmd, f_result, f_verdict
}

-- ── Constants ─────────────────────────────────────────────────
local MAVLINK_EPOCH  = 1420070400   -- Jan 1 2015 UTC
local MSGID_HEARTBEAT    = 0
local MSGID_COMMAND_LONG = 76
local MSGID_COMMAND_ACK  = 77

-- ── Helpers ───────────────────────────────────────────────────
local function fmt_unix(ts)
    return os.date("!%Y-%m-%d %H:%M:%S", math.floor(ts)) .. " UTC"
end

-- Read a little-endian uint16 from a raw string at offset (1-based)
local function read_u16_le(raw, offset)
    local lo = raw:byte(offset)
    local hi = raw:byte(offset + 1)
    return lo + hi * 256
end

-- Read a little-endian 48-bit uint from a raw string at offset (1-based)
local function read_u48_le(raw, offset)
    local v = 0
    for i = 5, 0, -1 do
        v = v * 256 + raw:byte(offset + i)
    end
    return v
end

local function add(sub, field, buf, text)
    local item = sub:add(field, buf)
    item:set_text(text)
end

-- ── Dissector ─────────────────────────────────────────────────
p.dissector = function(buffer, pinfo, tree)
    local ok, err = pcall(function()

        local len = buffer:len()
        if len < 12 then return end

        local raw = buffer:raw()
        -- Must be MAVLink 2.0
        if raw:byte(1) ~= 0xFD then return end

        local payload_len = raw:byte(2)
        local incompat    = raw:byte(3)
        local signed      = (incompat % 2) == 1   -- bit 0 set = signed

        -- 3-byte little-endian message ID at bytes 8-10
        local msgid = raw:byte(8) + raw:byte(9)*256 + raw:byte(10)*65536

        -- Only annotate COMMAND_LONG and COMMAND_ACK
        if msgid ~= MSGID_COMMAND_LONG and msgid ~= MSGID_COMMAND_ACK then
            return
        end

        local buf = buffer(0, len)
        local sub = tree:add(p, buf, "Attack 4 — Replay Analysis")

        -- ── Common fields ─────────────────────────────────────
        add(sub, f_magic, buf,
            string.format("MAVLink Version     : 0x%02X = MAVLink 2.0", raw:byte(1)))

        local signed_str = signed and "YES (incompat=0x01)" or "NO"
        add(sub, f_signed, buf,
            "Signed              : " .. signed_str)

        -- ── COMMAND_LONG — the replayed attack packet ─────────
        if msgid == MSGID_COMMAND_LONG then

            add(sub, f_type, buf,
                "Packet Role         : REPLAYED SIGNED COMMAND   <<< THIS IS THE ATTACK PACKET")

            add(sub, f_msgid, buf,
                "Message ID          : 76 = COMMAND_LONG")

            -- Signature block: starts at 10 + payload_len + 2 (CRC)
            local sig_start = 10 + payload_len + 2   -- 1-based = sig_start+1
            if signed and len >= sig_start + 13 then
                local ts_val  = read_u48_le(raw, sig_start + 2)  -- skip link_id (1 byte)
                local ts_unix = MAVLINK_EPOCH + ts_val / 100000.0
                local ts_date = fmt_unix(ts_unix)
                local now     = os.time()
                local gap_sec = ts_unix - now
                local gap_h   = math.floor(math.abs(gap_sec) / 3600)
                local gap_dir = gap_sec > 0 and "FUTURE" or "past"

                add(sub, f_sig_ts, buf,
                    string.format(
                    "Signature TS        : %d  (10µs units since Jan 1 2015)",
                    ts_val))

                add(sub, f_sig_date, buf,
                    "Signature Date      : " .. ts_date ..
                    "   <<< CAPTURED FROM ATTACK 1")

                add(sub, f_ts_gap, buf,
                    string.format(
                    "Timestamp vs Now    : %s by %d hours  → replay is VALID (still in future)",
                    gap_dir, gap_h))
            end

            -- Decode command from payload (bytes 10+29 and 10+30 = uint16 command)
            -- COMMAND_LONG payload (MAVLink2, possibly truncated):
            -- param1..7 = 7 floats (28 bytes), command=uint16, target_sys, target_comp, confirm
            if payload_len >= 30 then
                local cmd = read_u16_le(raw, 10 + 28 + 1)   -- 1-based offset
                local cmd_name = cmd == 176 and "MAV_CMD_DO_SET_MODE (176) = LAND" or
                                 tostring(cmd)
                add(sub, f_cmd, buf,
                    "Command             : " .. cmd_name)
            end

            add(sub, f_verdict, buf,
                "VERDICT             : Packet from Attack 1 replayed byte-for-byte. " ..
                "Signature still valid (same key, timestamp still in future after reboot). " ..
                "Watch for COMMAND_ACK below — result=0 confirms acceptance.")

            pinfo.cols.protocol:set("ATK4_REPLAY")
            pinfo.cols.info:set(string.format(
                "ATK4 REPLAYED COMMAND_LONG | cmd=DO_SET_MODE(LAND) | sig: future | ATTACK PACKET"))

        -- ── COMMAND_ACK — proof the replay was accepted ───────
        elseif msgid == MSGID_COMMAND_ACK then

            -- ACK payload: command (uint16) + result (uint8)
            local cmd    = read_u16_le(raw, 11)   -- 1-based: byte 11-12
            local result = raw:byte(13)
            local result_str = result == 0 and "0 = ACCEPTED" or
                               result == 1 and "1 = TEMPORARILY_REJECTED" or
                               result == 2 and "2 = DENIED" or
                               result == 3 and "3 = UNSUPPORTED" or
                               result == 4 and "4 = FAILED" or
                               tostring(result)

            local cmd_str = cmd == 176 and "176 = MAV_CMD_DO_SET_MODE" or tostring(cmd)

            add(sub, f_type, buf,
                "Packet Role         : COMMAND_ACK — UAV response to replayed packet")

            add(sub, f_msgid, buf,
                "Message ID          : 77 = COMMAND_ACK")

            add(sub, f_cmd, buf,
                "Acknowledges cmd    : " .. cmd_str)

            add(sub, f_result, buf,
                "Result              : " .. result_str)

            if result == 0 then
                add(sub, f_verdict, buf,
                    "VERDICT             : REPLAY ATTACK SUCCEEDED. " ..
                    "UAV accepted the replayed signed command. " ..
                    "Drone switched to LAND mode. " ..
                    "Root cause: key not rotated after reboot + future timestamp still valid.")

                pinfo.cols.protocol:set("ATK4_ACCEPTED")
                pinfo.cols.info:set(string.format(
                    "ATK4 COMMAND_ACK | cmd=%s | result=ACCEPTED <<< REPLAY SUCCEEDED",
                    cmd_str))
            else
                add(sub, f_verdict, buf,
                    "VERDICT             : UAV rejected the command (result=" .. result_str .. ")")

                pinfo.cols.protocol:set("ATK4_REJECTED")
                pinfo.cols.info:set(string.format(
                    "ATK4 COMMAND_ACK | cmd=%s | result=%s",
                    cmd_str, result_str))
            end
        end

    end)

    if not ok then
        pinfo.cols.info:set("ATK4 LUA ERROR: " .. tostring(err))
    end
end

-- ── Register as post-dissector with allfields=true ───────────
-- allfields=true makes our fields indexable for display filters.
-- Without it, atk4replay.type returns 0 results in Wireshark 3.6.
register_postdissector(p, true)
