-- handler.lua
local BasePlugin = require "kong.plugins.base_plugin"
local http = require("resty.http")
local url = require "socket.url"

local kong = kong


local OidcRefreshTokenHandler = BasePlugin:extend()


OidcRefreshTokenHandler.VERSION  = "1.0.0"
OidcRefreshTokenHandler.PRIORITY = 10

local parsed_urls_cache = {}


-- Parse host url.
-- @param `url` host url
-- @return `parsed_url` a table with host details:
-- scheme, host, port, path, query, userinfo
local function parse_url(host_url)
  
  local parsed_url = parsed_urls_cache[host_url]

  if parsed_url then
    return parsed_url
  end

  parsed_url = url.parse(host_url)
  if not parsed_url.port then
    if parsed_url.scheme == "http" then
      parsed_url.port = 80
    elseif parsed_url.scheme == "https" then
      parsed_url.port = 443
    end
  end
  if not parsed_url.path then
    parsed_url.path = "/"
  end

  parsed_urls_cache[host_url] = parsed_url

  return parsed_url
end

function OidcRefreshTokenHandler:new()
  OidcRefreshTokenHandler.super.new(self, "oidc-refresh-token-atez")
end

function OidcRefreshTokenHandler:access(config)
  OidcRefreshTokenHandler.super.access(self)

  -- kong.log.inspect(config.environment) -- "development"
  -- kong.log.inspect(config.server.host) -- "http://localhost"
  -- kong.log.inspect(config.server.port) -- 80
  
  -- local headers = kong.request.get_headers()
  local authStr = ngx.req.get_headers()["Authorization"]
  if authStr then
        
    local reqBody = {
      grant_type = 'refresh_token',
      refresh_token = authStr,
    }    
    
    local http_endpoint = config.serverUrl .. '/realms/' .. config.realm .. '/protocol/openid-connect/token';
        
    local ok, err
    local parsed_url = parse_url(http_endpoint)
    local host = parsed_url.host
    local port = tonumber(parsed_url.port)    
    local msg
    
    local httpc = http.new()
    httpc:set_timeout(timeout)
    ok, err = httpc:connect(host, port)
    if not ok then
      msg = "failed to connect to " .. host .. ":" .. tostring(port) .. ": " .. err
      kong.log.err(msg, err)
      return kong.response.exit(ngx.HTTP_UNAUTHORIZED, msg)
    end    
    
    if parsed_url.scheme == "https" then
      local _, err = httpc:ssl_handshake(true, host, false)
      if err then
        msg = "failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": " .. err
        kong.log.err(msg, err)
        return kong.response.exit(ngx.HTTP_UNAUTHORIZED, msg)
      end
    end  
       
    local payload = ngx.encode_args(reqBody)
    local res, err = httpc:request({
      method = 'POST',
      path = parsed_url.path,
      query = parsed_url.query,
      headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
        ["X-Client"] = "keycloak-kong-connect",
        ["User-Agent"] = "KONG",
        ["accept"] = "*/*",        
        ["Authorization"] = "Basic " .. ngx.encode_base64(config.resource .. ":" .. config.secret),
        ["Content-Length"] = #payload,        
      },
      body = payload,
    })
    if not res then
      msg = "failed request to " .. host .. ":" .. tostring(port) .. ": " .. err
      kong.log.err(msg, err)
      return kong.response.exit(ngx.HTTP_UNAUTHORIZED, msg)
    end    

    -- always read response body, even if we discard it without using it on success
    local response_body = res:read_body()
    local success = res.status < 400

    if not success then
      msg = "request to " .. host .. ":" .. tostring(port) ..
            " returned status code " .. tostring(res.status) .. " and body " ..
            response_body
      kong.log.err(msg, err)
      return kong.response.exit(ngx.HTTP_UNAUTHORIZED, msg)
    end
  
    ok, err = httpc:set_keepalive(keepalive)
    if not ok then
      -- the batch might already be processed at this point, so not being able to set the keepalive
      -- will not return false (the batch might not need to be reprocessed)
      kong.log.err("failed keepalive for ", host, ":", tostring(port), ": ", err)
    end

    --ngx.log(ngx.DEBUG, "================================================================================\n")
    --ngx.log(ngx.DEBUG, "Start Authenticate...\n")
    --ngx.log(ngx.DEBUG, response_body .."\n")
    --ngx.log(ngx.DEBUG, "================================================================================\n") 

    return kong.response.exit(ngx.HTTP_OK, response_body, { ["Content-Type"] = "application/json" })
  else 
    return kong.response.exit(ngx.HTTP_UNAUTHORIZED, "No Authorization Header found")
  end
end


return OidcRefreshTokenHandler