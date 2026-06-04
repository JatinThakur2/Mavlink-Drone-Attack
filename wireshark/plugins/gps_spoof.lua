-- =============================================================
-- gps_spoof.lua  —  GPS_INPUT packet decoder for all attack zones
-- UDP port 25100 (MAVProxy GPSInput module)
--
-- Detects 3 attack zones by time_usec value:
--
--   ZONE 0  time_usec < 1,420,070,400,000,000   →  Pre-2015 (underflow)
--   ZONE 2  time_usec < 3,000,000,000,000,000   →  Clock advance (Attack 2)
--   ZONE 3  time_usec ≥ 3,000,000,000,000,000   →  Overflow DoS (Attack 3)
--
-- Restart Wireshark after saving this file.
-- =============================================================

local p = Proto("atk2gps", "Attack2 GPS Spoof")

-- ── Shared ────────────────────────────────────────────────────
local f_attack   = ProtoField.string("atk2gps.attack",    "Attack Type")
local f_json     = ProtoField.string("atk2gps.json",      "Raw JSON")

-- ── Zone 0: Pre-2015 (underflow) ──────────────────────────────
local f_u_date   = ProtoField.string("atk2gps.u_date",    "GPS Date (pre-epoch)")
local f_u_mav    = ProtoField.string("atk2gps.u_mav",     "MAVLink TS (signed)")
local f_u_wrap   = ProtoField.string("atk2gps.u_wrap",    "uint64 Wrapped Value")
local f_u_effect = ProtoField.string("atk2gps.u_effect",  "Signing Effect")

-- ── Zone 2: Attack 2 (clock advance) ──────────────────────────
local f_gps_date = ProtoField.string("atk2gps.gps_date",  "GPS Date Claimed")
local f_cap_date = ProtoField.string("atk2gps.cap_date",  "Capture Date (real)")
local f_gap      = ProtoField.string("atk2gps.gap",       "Time Gap")
local f_lat      = ProtoField.string("atk2gps.lat",       "Latitude (fake)")
local f_drift    = ProtoField.string("atk2gps.drift",     "Position Drift")

-- ── Zone 3: Attack 3 (overflow DoS) ───────────────────────────
local f_ovf_date = ProtoField.string("atk2gps.ovf_date",  "Overflow GPS Date")
local f_ovf_gap  = ProtoField.string("atk2gps.ovf_gap",   "Years Ahead")
local f_mav_ts   = ProtoField.string("atk2gps.mav_ts",    "MAVLink Signing TS")
local f_mav_max  = ProtoField.string("atk2gps.mav_max",   "48-bit MAX (2^48-1)")
local f_mav_rem  = ProtoField.string("atk2gps.mav_rem",   "Units Below MAX")
local f_dos      = ProtoField.string("atk2gps.dos",       "DoS Effect")
local f_recover  = ProtoField.string("atk2gps.recover",   "Recovery Method")

p.fields = {
    f_attack, f_json,
    f_u_date, f_u_mav, f_u_wrap, f_u_effect,
    f_gps_date, f_cap_date, f_gap, f_lat, f_drift,
    f_ovf_date, f_ovf_gap, f_mav_ts, f_mav_max, f_mav_rem, f_dos, f_recover
}

-- ── Constants ─────────────────────────────────────────────────
local HOME_LAT          = -35.363261
local SPOOF_DAYS        = 10
local MAVLINK_EPOCH     = 1420070400        -- Jan 1 2015 UTC (Unix seconds)
local MAVLINK_EPOCH_US  = 1420070400 * 1e6  -- same in microseconds
local MAX_48BIT         = 281474976710655   -- 2^48 - 1  (fits in double)
local ATK3_THRESHOLD    = 3000000000000000  -- zone 3 threshold for time_usec

-- Pre-computed underflow values for Jan 1 2010 (avoids Lua double overflow).
-- Lua uses double (max exact integer = 2^53). UINT64_MAX = 2^64 - 1 cannot
-- be represented exactly, so we pre-compute and store as strings.
--   UNDERFLOW_UNIX   = 1262304000
--   MAV_TS_SIGNED    = (1262304000 - 1420070400) * 100000 = -15776640000000
--   UINT64_MAX       = 18446744073709551615
--   WRAPPED          = UINT64_MAX + MAV_TS_SIGNED + 1 = 18446728297069551616
--   48-BIT MASKED    = WRAPPED & (2^48-1) = 265698336710656
local MAV_TS_SIGNED_STR = "-15,776,640,000,000"
local WRAPPED_TS_STR    = "18,446,728,297,069,551,616"
local MASKED_48BIT      = 265698336710656   -- fits in double (< 2^53)

-- ── Helpers ───────────────────────────────────────────────────
local function json_num(text, key)
    local val = text:match('"' .. key .. '"%s*:%s*(%-?%d+%.?%d*)')
    return val and tonumber(val) or nil
end

local function fmt_unix(ts)
    return os.date("!%Y-%m-%d %H:%M:%S", math.floor(ts)) .. " UTC"
end

local function add(sub, field, buf, text)
    local item = sub:add(field, buf)
    item:set_text(text)
end

-- ── Dissector ─────────────────────────────────────────────────
p.dissector = function(buffer, pinfo, tree)
    local ok, err = pcall(function()

        local len = buffer:len()
        if len == 0 then return end

        local raw = buffer:raw()
        if not raw or raw:sub(1,1) ~= '{' then return end

        local time_usec = json_num(raw, "time_usec")
        local lat_raw   = json_num(raw, "lat")
        if not time_usec then return end

        local buf = buffer(0, len)

        -- ══════════════════════════════════════════════════════
        -- ZONE 0 — Pre-2015  (time_usec before MAVLink epoch)
        -- GPS date < Jan 1 2015 → MAVLink TS is negative
        -- As uint64 this wraps to near 2^64 → signing clock
        -- jumps to a value even larger than Attack 3 overflow
        -- ══════════════════════════════════════════════════════
        if time_usec < MAVLINK_EPOCH_US then

            pinfo.cols.protocol:set("ATK0_UNDERFLOW")
            local sub = tree:add(p, buf, "Attack 3B — Timestamp Underflow")

            add(sub, f_attack, buf,
                "Attack Zone         : ZONE 0 — Pre-MAVLink-Epoch GPS Date (Attack 3B)")

            local gps_unix = time_usec / 1e6
            add(sub, f_u_date, buf,
                "GPS Date Claimed    : " .. fmt_unix(gps_unix) ..
                "  (BEFORE MAVLink epoch Jan 1 2015)")

            -- All values pre-computed as strings to avoid Lua double overflow.
            -- Lua uses double precision (max exact integer = 2^53 ≈ 9e15).
            -- UINT64_MAX = 2^64-1 ≈ 1.8e19 cannot be stored exactly.
            -- Pre-computed for Jan 1 2010 (UNDERFLOW_UNIX = 1262304000):
            --   MAV_TS_SIGNED = -15,776,640,000,000
            --   WRAPPED       = 2^64 + MAV_TS_SIGNED = 18,446,728,297,069,551,616
            --   48-bit masked = WRAPPED & (2^48-1)   = 265,698,336,710,656
            add(sub, f_u_mav, buf,
                "MAVLink TS (signed) : " .. MAV_TS_SIGNED_STR ..
                "   (NEGATIVE — 5 years before MAVLink epoch)")

            add(sub, f_u_wrap, buf,
                "uint64 Wrapped TS   : " .. WRAPPED_TS_STR ..
                "   (2^64 + negative = wraps near 2^64)")

            add(sub, f_u_wrap, buf,
                string.format(
                "48-bit Masked Value : %d   (real 2026 TS ≈ 36,116,952,500,000)",
                MASKED_48BIT))

            add(sub, f_u_effect, buf,
                "EFFECT A — uint64 wrap DoS : 265 trillion >> 36 trillion. " ..
                "Rule 6 rejects all real 2026 packets. Same blackout as Attack 3.")

            add(sub, f_u_effect, buf,
                "EFFECT B — clamped to 0   : Signing clock resets to Jan 1 2015. " ..
                "All 2026 packets accepted again. Acts as CLOCK RESET.")

            if lat_raw then
                local lat = lat_raw / 1e7
                add(sub, f_lat, buf,
                    string.format("Position (fixed)    : lat=%.6f  (home — no drift)",
                        lat))
            end

            add(sub, f_json, buf, "Raw JSON : " .. raw:sub(1,100) .. "...")

            pinfo.cols.info:set(string.format(
                "ATK3B UNDERFLOW | GPS: %s | pre-2015 | TS negative | wraps near 2^64",
                os.date("!%Y-%m-%d", math.floor(gps_unix))))

        -- ══════════════════════════════════════════════════════
        -- ZONE 3 — Overflow DoS  (Attack 3)
        -- time_usec ≥ 3e15 → year ~2065+ → 48-bit boundary
        -- ══════════════════════════════════════════════════════
        elseif time_usec >= ATK3_THRESHOLD then

            pinfo.cols.protocol:set("ATK3_OVERFLOW")
            local sub = tree:add(p, buf, "Attack 3 — Timestamp Overflow DoS")

            add(sub, f_attack, buf,
                "Attack Zone         : ZONE 3 — 48-bit Overflow DoS (Attack 3)")

            local gps_unix  = time_usec / 1e6
            local real_unix = tonumber(os.time())
            local years_diff = (gps_unix - real_unix) / (365.25 * 86400)

            add(sub, f_ovf_date, buf,
                "Overflow GPS Date   : " .. fmt_unix(gps_unix) ..
                "  (year 2104 — 48-bit boundary)")

            add(sub, f_ovf_gap, buf,
                string.format(
                "Years Ahead         : ~%.0f years ahead of real time   <<< THE ATTACK",
                years_diff))

            local mav_ts  = math.floor((gps_unix - MAVLINK_EPOCH) * 100000)
            local mav_rem = MAX_48BIT - mav_ts

            add(sub, f_mav_ts, buf,
                string.format(
                "MAVLink Signing TS  : %d  (10µs units since Jan 1 2015)",
                mav_ts))

            add(sub, f_mav_max, buf,
                string.format(
                "48-bit MAX (2^48-1) : %d",
                MAX_48BIT))

            add(sub, f_mav_rem, buf,
                string.format(
                "Units Below MAX     : %d  (~%.3f seconds below ceiling",
                mav_rem, mav_rem / 100000))

            add(sub, f_dos, buf,
                "DoS Effect          : UAV signing clock → 2^48-1. " ..
                "All real 2026 packets appear ~78 years in the PAST → " ..
                "Rule 6 rejects every single signed command. Total blackout.")

            add(sub, f_recover, buf,
                "Recovery            : Firmware reflash ONLY — " ..
                "clock persists in EEPROM across reboots and key rotation")

            if lat_raw then
                local lat = lat_raw / 1e7
                add(sub, f_lat, buf,
                    string.format(
                    "Position (fixed)    : lat=%.6f  (no position drift — DoS needs only 1 packet)",
                    lat))
            end

            add(sub, f_json, buf, "Raw JSON : " .. raw:sub(1,100) .. "...")

            pinfo.cols.info:set(string.format(
                "ATK3 OVERFLOW DoS | GPS: %s | MAVLink ts: %d | ~%d yrs ahead | PERMANENT BLACKOUT",
                os.date("!%Y-%m-%d", math.floor(gps_unix)),
                mav_ts, math.floor(years_diff)))

        -- ══════════════════════════════════════════════════════
        -- ZONE 2 — Clock Advance  (Attack 2)
        -- time_usec between epoch and threshold → moderate future
        -- ══════════════════════════════════════════════════════
        else

            pinfo.cols.protocol:set("ATK2_GPS_SPOOF")
            local sub = tree:add(p, buf, "Attack 2 — GPS Timestamp + Position Spoof")

            add(sub, f_attack, buf,
                "Attack Zone         : ZONE 2 — Clock Advance + Position Drift (Attack 2)")

            local gps_unix  = time_usec / 1e6
            local real_unix = gps_unix - (SPOOF_DAYS * 86400)
            local gap_hrs   = math.floor(((gps_unix - real_unix) % 86400) / 3600)

            add(sub, f_gps_date, buf,
                "GPS Date Claimed    : " .. fmt_unix(gps_unix))
            add(sub, f_cap_date, buf,
                "Capture Date (real) : " .. fmt_unix(real_unix))
            add(sub, f_gap, buf,
                string.format(
                "Time Gap            : +%d days %d hours   <<< THE ATTACK",
                SPOOF_DAYS, gap_hrs))

            if lat_raw then
                local lat     = lat_raw / 1e7
                local drift_m = math.abs(lat - HOME_LAT) * 111320
                add(sub, f_lat, buf,
                    string.format(
                    "Latitude  (fake)    : %.6f   (real home: %.6f)",
                    lat, HOME_LAT))
                add(sub, f_drift, buf,
                    string.format(
                    "Position Drift      : %.0f m south   <<< DRONE FLIES NORTH",
                    drift_m))
            end

            add(sub, f_json, buf, "Raw JSON : " .. raw:sub(1,120) .. "...")

            local lat_s   = lat_raw and string.format("%.4f",  lat_raw/1e7) or "?"
            local drift_s = lat_raw and
                string.format("%.0fm", math.abs(lat_raw/1e7 - HOME_LAT)*111320) or "?"

            pinfo.cols.info:set(string.format(
                "ATK2 GPS Spoof | claimed: %s (+%dd) | lat: %s | drift: %s S",
                os.date("!%b %d", math.floor(gps_unix)), SPOOF_DAYS, lat_s, drift_s))
        end

    end)

    if not ok then
        pinfo.cols.info:set("GPS_SPOOF LUA ERROR: " .. tostring(err))
        pinfo.cols.protocol:set("GPS_ERR")
    end
end

-- ── Register on UDP port 25100 ────────────────────────────────
DissectorTable.get("udp.port"):add(25100, p)
