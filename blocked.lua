-- /etc/knot-resolver/blocked.lua
local ffi = require('ffi')
local knot_rrset_t = ffi.typeof('knot_rrset_t')

local blocked = {}

-- Path of the kres-netlinkd daemon's Unix socket.
local SOCKET_PATH = '/var/lib/knot-resolver/kres-netlinkd.sock'

-- POSIX socket bindings used to talk to the daemon over AF_UNIX/SOCK_STREAM.
local AF_UNIX = 1
local SOCK_STREAM = 1

ffi.cdef[[
struct sockaddr_un {
  unsigned short sun_family;
  char           sun_path[108];
};

int     socket(int domain, int type, int protocol);
int     connect(int sockfd, const void *addr, unsigned int addrlen);
long    read(int fd, void *buf, unsigned long count);
long    write(int fd, const void *buf, unsigned long count);
int     close(int fd);
]]

-- warn logs a diagnostic line without depending on a specific resolver log API.
local function warn(msg)
  io.stderr:write("blocked.lua: " .. msg .. "\n")
end

-- json_array renders a Lua list of strings as a JSON array, quoting each item.
local function json_array(items)
  local parts = {}
  for _, v in ipairs(items) do
    table.insert(parts, '"' .. v .. '"')
  end
  return "[" .. table.concat(parts, ",") .. "]"
end

-- send_update sends one combined JSON Message to the daemon and blocks until it
-- reads one OK/NOK line. It returns true only on an "OK" reply; any error or a
-- "NOK" reply is logged and returns false so DNS resolution can proceed.
local function send_update(name, a_ips, aaaa_ips)
  local req = string.format('{"name":"%s","ipv4":%s,"ipv6":%s}\n',
    name, json_array(a_ips), json_array(aaaa_ips))

  local fd = ffi.C.socket(AF_UNIX, SOCK_STREAM, 0)
  if fd < 0 then
    warn("failed to create socket")
    return false
  end

  local ok = false

  local err = (function()
    local addr = ffi.new('struct sockaddr_un')
    addr.sun_family = AF_UNIX
    if #SOCKET_PATH >= ffi.sizeof(addr.sun_path) then
      return "socket path too long"
    end
    ffi.copy(addr.sun_path, SOCKET_PATH)

    if ffi.C.connect(fd, addr, ffi.sizeof('struct sockaddr_un')) ~= 0 then
      return "connect failed"
    end

    -- Write the whole request line.
    local data = req
    local total = #data
    local sent = 0
    while sent < total do
      local n = ffi.C.write(fd, ffi.cast('const char *', data) + sent, total - sent)
      if n <= 0 then
        return "write failed"
      end
      sent = sent + n
    end

    -- Read until we have a full response line.
    local resp = ""
    local buf = ffi.new('char[64]')
    while not resp:find("\n", 1, true) do
      local n = ffi.C.read(fd, buf, ffi.sizeof(buf))
      if n <= 0 then
        return "read failed"
      end
      resp = resp .. ffi.string(buf, n)
    end

    local line = resp:match("^[^\n]*")
    line = line:gsub("%s+$", "")
    ok = (line == "OK")
    return nil
  end)()

  ffi.C.close(fd)

  if err then
    warn(string.format("update for %q failed: %s", name, err))
    return false
  end
  if not ok then
    warn(string.format("update for %q rejected (NOK)", name))
  end
  return ok
end

package.path = package.path .. ";/etc/knot-resolver/?.lua"
local dstNames = require('blocked-map')

local trie = {}

for vpn_target, domains in pairs(dstNames) do
  for _, domain in ipairs(domains) do
    local parts = {}
    for part in domain:lower():gmatch("[^%.]+") do
      table.insert(parts, 1, part)
    end

    local current = trie
    for _, part in ipairs(parts) do
      if not current[part] then
        current[part] = {}
      end
      current = current[part]
    end
    current._target = vpn_target
  end
end

local function find_vpn_target(qname_str)
  local current = trie
  local last_target = nil

  local qname_lower = qname_str:lower()
  local len = #qname_lower

  if len <= 1 then return nil end

  local last_pos = len
  while last_pos > 1 do
    local first_pos = 1

    for i = last_pos - 1, 1, -1 do
      if qname_lower:byte(i) == 46 then -- 46 = '.'
        first_pos = i + 1
        break
      end
    end

    local label = qname_lower:sub(first_pos, last_pos - 1)

    current = current[label]
    if not current then
      break
    end

    if current._target then
      last_target = current._target
    end

    last_pos = first_pos - 1
  end

  return last_target
end

blocked.layer = {
  consume = function (state, req, pkt)
    local qt = pkt:qtype()
    if qt == kres.type.A or qt == kres.type.AAAA then
      local qname_str = kres.dname2str(pkt:qname())
      local vpn_target = find_vpn_target(qname_str)

      if vpn_target then
        local records = pkt:section(kres.section.ANSWER)
        local a_ips = {}
        local aaaa_ips = {}

        for i = 1, #records do
          local rr = records[i]
          if rr.type == kres.type.A or rr.type == kres.type.AAAA then
            local rrs = knot_rrset_t(rr.owner, rr.type, kres.class.IN, rr.ttl)
            rrs:add_rdata(rr.rdata, #rr.rdata)
            local ret = rrs:txt_fields(0)

            if rr.type == kres.type.A then
              table.insert(a_ips, ret.rdata)
            elseif rr.type == kres.type.AAAA then
              table.insert(aaaa_ips, ret.rdata)
            end
          end
        end

        if #a_ips > 0 or #aaaa_ips > 0 then
          send_update(vpn_target, a_ips, aaaa_ips)
        end
      end
    end
    return state
  end
}

return blocked
