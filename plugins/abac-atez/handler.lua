-- handler.lua
local BasePlugin = require "kong.plugins.base_plugin"
local utils = require("kong.plugins.abac-atez.utils")
local filter = require("kong.plugins.abac-atez.filter")
local session = require("kong.plugins.abac-atez.session")
local http = require("resty.http")
local url = require "socket.url"
local cjson_safe = require("cjson.safe")

local kong = kong

local AbacHandler = BasePlugin:extend()

AbacHandler.VERSION  = "1.0.0"
AbacHandler.PRIORITY = 1000
local M = {}


function AbacHandler:new()
  AbacHandler.super.new(self, "abac-atez")
end

function AbacHandler:access(config)
  AbacHandler.super.access(self)
  
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    M.handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")

end

function M.handle(oidcConfig)
  --ngx.log(ngx.DEBUG, "================================================================================\n")
  --ngx.log(ngx.DEBUG, "Start ABAC Authenticate...\n")
  --ngx.log(ngx.DEBUG, "0000001\n")
  --ngx.log(ngx.DEBUG, "================================================================================\n")    
  local response
  --ngx.log(ngx.DEBUG, "================================================================================\n")
  --ngx.log(ngx.DEBUG, "Start Handler...\n")
  --ngx.log(ngx.DEBUG, "================================================================================\n")  
  if oidcConfig.introspection_endpoint then
    --ngx.log(ngx.DEBUG, "================================================================================\n")
    --ngx.log(ngx.DEBUG, "Start Introspect...\n")
    --ngx.log(ngx.DEBUG, "================================================================================\n")
    --ngx.log(ngx.DEBUG, "OidcHandler calling Introspect, endpoint : "..oidcConfig.introspection_endpoint)
    
   
    
    response = M.introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    --ngx.log(ngx.DEBUG, "================================================================================\n")
    --ngx.log(ngx.DEBUG, "Start Authenticate...\n")
    --ngx.log(ngx.DEBUG, "================================================================================\n")
    response = M.make_oidc(oidcConfig)
    if response then
      if (response.user) then
        utils.injectUser(response.user)
      end
      if (response.access_token) then
        utils.injectAccessToken(response.access_token)
      end
      if (response.id_token) then
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

function M.make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function M.getScopes_rbac(json,claim)

  if type(json) == "table" then
    ngx.log(ngx.DEBUG, "JSON : " .. utils.table_to_string(json))
  end

  local claimParsed = {}
  for w in claim:gmatch("([^.]+)") do claimParsed[#claimParsed + 1] = w end
  local val=json
  
  --xPath for jSON as a.b.roles
  for i = 1 , #claimParsed do
    val = val[claimParsed[i]]
    if val == nil then return {} end 
  end
  
  local claims = {}
  -- isPathFound is Table(Array or Object) get roles from properties 
  if type(val) == "table" then
    for k, v in pairs(val) do
      if type(k) == "string" then
        table.insert(claims, k)
      elseif type(k) == "number" then
        table.insert(claims, v)  
      end  
    end
  -- isPathFound is scalar get result by parsing space delimited strings
  elseif type(val) == "string" then
    for w in val:gmatch("([^%s]+)") do claims[#claims + 1] = w end
  end
   
  return claims
  
end

function M.authorize_scope_rbac(json,opts)
  local authorized=false;

  --ngx.log(ngx.DEBUG, "opts : " .. utils.table_to_string(opts))
  --ngx.log(ngx.DEBUG, "Scopes Required : " .. tostring(opts.scopes_required) .. " Scopes Claim : " .. tostring(opts.scopes_claim))
  if opts.scopes_required == nil then
    authorized=true
    return authorized  
  end
  
  -- parse scopes required ==> extract openid ==> ";" means "and" %s means "or"    
  local scopes_required = {}
  local scopes_required_size = 0;
  local scopes_and = string.find(opts.scopes_required, ";")
  local sr = string.gsub(opts.scopes_required, "openid", "")
  if scopes_and then
    for w in sr:gmatch("([^;]+)") do 
      scopes_required[w] = false
      scopes_required_size = scopes_required_size + 1 
     end  
  else
    for w in sr:gmatch("([^%s]+)") do 
      scopes_required[w] = false
      scopes_required_size = scopes_required_size + 1 
    end  
  end
  if scopes_required_size == 0 then
    authorized=true
    return authorized
  end
  ngx.log(ngx.DEBUG, "-------------- Scopes Required : " .. utils.table_to_string(scopes_required))

  -- parse json pathes to collect requested scopes
  local scopes_claim = {}
  for w in opts.scopes_claim:gmatch("([^;]+)") do scopes_claim[#scopes_claim + 1] = w end
  ngx.log(ngx.DEBUG, "--------------- Scopes Claim : " .. utils.table_to_string(scopes_claim))


  -- collect scopes required
  local scopes = {}
  for i=1, #scopes_claim do
    scopes = M.getScopes_rbac(json,scopes_claim[i])
    --print(table_to_string(scopes))
    -- if scopes will be "or" any scopes_required true will authorize
    for k, v in pairs(scopes) do
      if scopes_required[v] ~= nil then 
        scopes_required[v]=true;
        if not scopes_and then
          authorized=true;
          return authorized;
        end; 
      end 
    end
     
  end
  ngx.log(ngx.DEBUG, "--------------- Scopes Required Calculated : " .. utils.table_to_string(scopes_required))  
  -- if scopes will be "and" then each scopes_required must be true
  if scopes_and then
    for k, v in pairs(scopes_required) do
      if not v then
        authorized=false;
        return authorized
      end
    end;
    authorized=true      
  end
  
  return authorized;
end

function M.authorize_abac(json,oidcConfig)
  local abac_rules = cjson_safe.decode(oidcConfig.abac_rules)
  local rule = {};
  local found = false;
  local contextfn;
  local reqBody = {};
  local authorized = false;
  local expected_permissions = {}
  for _, arule in pairs(abac_rules) do
    if (arule.method == ngx.req.get_method()) and (string.find(ngx.var.uri, arule.path)) then
      found=true;
      rule = arule;
      break;
    end
  end  
  if found then
    reqBody.grant_type = "urn:ietf:params:oauth:grant-type:uma-ticket"
    reqBody.audience =  oidcConfig.client_id
    reqBody.response_mode = "permissions"    
    
    if rule.context ~= "" then
      contextfn = loadstring(oidcConfig.context .."\n return ".. rule.context);      
      local contexttbl, err = contextfn();
      --ngx.log(ngx.DEBUG, "================================================================================\n")
      --ngx.log(ngx.DEBUG, "Start function Cuneyt 2...\n")
      --ngx.log(ngx.DEBUG,  cjson_safe.encode(contexttbl).."\n")
      --ngx.log(ngx.DEBUG, "================================================================================\n")                        
      reqBody.claimTokenFormat = "urn:ietf:params:oauth:token-type:jwt";  
      if contexttbl ~= nil then
        reqBody.claimToken = ngx.encode_base64(cjson_safe.encode(contexttbl))
        --ngx.log(ngx.DEBUG, "================================================================================\n")
        --ngx.log(ngx.DEBUG, "Start function Cuneyt 3...\n")
        --ngx.log(ngx.DEBUG,  reqBody.claimToken.."\n")
        --ngx.log(ngx.DEBUG, "================================================================================\n")            
            
      end  
    end
    
    --ngx.log(ngx.DEBUG, "================================================================================\n")
    --ngx.log(ngx.DEBUG, "Start function Cuneyt 4...\n")
    local authStr = ngx.req.get_headers()["Authorization"]
    if authStr and (string.find(authStr,'bearer ') or string.find(authStr,'Bearer ')) then
      reqBody.subject_token = string.sub(authStr, 8);
    end
    
    -- Permissions     
    if (not (rule.permissions == nil)) then
      
      for permission in string.gmatch(rule.permissions, "[^,]+") do
        table.insert(expected_permissions, permission)
      end
      if #expected_permissions == 1 then
        reqBody.permission = expected_permissions[0]
      elseif #expected_permissions > 1 then  
        reqBody.permission = expected_permissions
      end
    end
    
    local http_endpoint = oidcConfig.serverUrl .. '/realms/' .. oidcConfig.realm .. '/protocol/openid-connect/token';
        
    local ok, err
    local parsed_url = url.parse(http_endpoint)
    local host = parsed_url.host
    local port = tonumber(parsed_url.port)    
    local msg
    
    local httpc = http.new()
    httpc:set_timeout(timeout)
    ok, err = httpc:connect(host, port)
    if not ok then
      msg = "failed to connect to " .. host .. ":" .. tostring(port) .. ": " .. err
      kong.log.err(msg, err)
      return false;
    end    
    
    if parsed_url.scheme == "https" then
      local _, err = httpc:ssl_handshake(true, host, false)
      if err then
        msg = "failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": " .. err
        kong.log.err(msg, err)
        return false;
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
        ["Authorization"] = "Basic " .. ngx.encode_base64(oidcConfig.client_id .. ":" .. oidcConfig.client_secret),
        ["Content-Length"] = #payload,        
      },
      body = payload,
    })
    if not res then
      msg = "failed request to " .. host .. ":" .. tostring(port) .. ": " .. err
      kong.log.err(msg, err)
      return false;
    end        
    
    -- always read response body, even if we discard it without using it on success
    local response_body = res:read_body()
    local success = res.status < 400

    if not success then
      msg = "request to " .. host .. ":" .. tostring(port) ..
            " returned status code " .. tostring(res.status) .. " and body " ..
            response_body
      kong.log.err(msg, err)
      return false
    end
  
    ok, err = httpc:set_keepalive(keepalive)
    if not ok then
      -- the batch might already be processed at this point, so not being able to set the keepalive
      -- will not return false (the batch might not need to be reprocessed)
      kong.log.err("failed keepalive for ", host, ":", tostring(port), ": ", err)
    end

    local existing_permissions = cjson_safe.decode(response_body)


    for _, permission in pairs(expected_permissions) do
      local expected = {}
      for permission in string.gmatch(rule.permissions, "[^#]+") do
        table.insert(expected, permission)
      end
      
      local resource = expected[1];
      local scope = nil;
      if #expected>1 then
        scope = expected[2];
      end
      
      --ngx.log(ngx.DEBUG, "================================================================================\n")
      --ngx.log(ngx.DEBUG, "Start function Cuneyt resource-scope...\n")
      --ngx.log(ngx.DEBUG, resource.." resource \n")
      --ngx.log(ngx.DEBUG, scope.." scope \n")
      --ngx.log(ngx.DEBUG, "================================================================================\n")       
      
      if (existing_permissions == nil) or (#existing_permissions == 0) then 
        return false;
      end      
      
      local resourcefound = false;
      for _, existing_permission in pairs(existing_permissions) do
        if (existing_permission.rsid == resource) or (existing_permission.rsname == resource) then
          resourcefound = true;
          if (scope ~= nil) then
            scopefound = false;
            local existing_scopes = existing_permission.scopes
            for _, existing_scope in pairs(existing_scopes) do
              if existing_scope == scope then
                scopefound = true;
                break
              end;              
            end
            if scopefound == false then 
              return false
            end
          end
        end
      end
      if resourcefound == false then
        return false
      end  
    end

    authorized = true
    return authorized  
    
  end
  
  return authorized;
end

function M.introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    
    if oidcConfig.access_type == "RBAC"  then  
      local auth = M.authorize_scope_rbac(res,oidcConfig)
      if not auth then
          ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",scopes required="' .. oidcConfig.scopes_required .. '"'
          utils.exit(ngx.HTTP_UNAUTHORIZED, "UnAuthorized...", ngx.HTTP_UNAUTHORIZED)    
      end
    elseif oidcConfig.access_type == "ABAC" then
      local auth = M.authorize_abac(res,oidcConfig)
 
      ngx.log(ngx.DEBUG, "================================================================================\n")
      ngx.log(ngx.DEBUG, "ABAC RESULT...\n")
      if auth then ngx.log(ngx.DEBUG,  "Auth=True") else ngx.log(ngx.DEBUG,  "Auth=False") end
      ngx.log(ngx.DEBUG, "================================================================================\n")       
      if not auth then
          ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",scopes required="' .. oidcConfig.scopes_required .. '"'
          utils.exit(ngx.HTTP_UNAUTHORIZED, "UnAuthorized...", ngx.HTTP_UNAUTHORIZED)    
      end
    end
  
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

return AbacHandler