local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local openidc = require("kong.plugins.oidc.openidc")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  ngx.log(ngx.DEBUG, "Start Handler...")
  if oidcConfig.introspection_endpoint then
    ngx.log(ngx.DEBUG, "OidcHandler calling Introspect, endpoint : "..oidcConfig.introspection_endpoint)
    response = introspect(oidcConfig)
    if response then
      utils.injectUser(response)
    end
  end

  if response == nil then
    response = make_oidc(oidcConfig)
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

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  --local res, err = require("resty.openidc").authenticate(oidcConfig)
  local res, err = openidc.authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

function getScopes(json,claim)

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

function authorize_scope(json,opts)
  local authorized=false;

  ngx.log(ngx.DEBUG, "opts : " .. utils.table_to_string(opts))
  ngx.log(ngx.DEBUG, "Scopes Required : " .. tostring(opts.scopes_required) .. " Scopes Claim : " .. tostring(opts.scopes_claim))
  if opts.scopes_required == nil then
    authorized=true
    return authorized  
  end
  
  -- parse scopes required ; means "and" %s means "or"    
  local scopes_required = {}
  local scopes_required_size = 0;
  local scopes_and = string.find(opts.scopes_required, ";")
  if scopes_and then
    for w in opts.scopes_required:gmatch("([^;]+)") do 
      scopes_required[w] = false
      scopes_required_size = scopes_required_size + 1 
     end  
  else
    for w in opts.scopes_required:gmatch("([^%s]+)") do 
      scopes_required[w] = false
      scopes_required_size = scopes_required_size + 1 
    end  
  end
  if scopes_required_size == 0 then
    authorized=true
    return authorized
  end
  ngx.log(ngx.DEBUG, "Scopes Required : " .. utils.table_to_string(scopes_required))

  -- parse json pathes to collect requested scopes
  local scopes_claim = {}
  for w in opts.scopes_claim:gmatch("([^;]+)") do scopes_claim[#scopes_claim + 1] = w end
  ngx.log(ngx.DEBUG, "Scopes Claim : " .. utils.table_to_string(scopes_claim))


  -- collect scopes required
  local scopes = {}
  for i=1, #scopes_claim do
    scopes = getScopes(json,scopes_claim[i])
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
  ngx.log(ngx.DEBUG, "Scopes Required Calculated : " .. utils.table_to_string(scopes_required))  
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

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    --local res, err = require("resty.openidc").introspect(oidcConfig)
    local res, err = openidc.introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    
    local auth = authorize_scope(res,oidcConfig)
    if not auth then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",scopes required="' .. oidcConfig.scopes_required .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, "UnAuthorized...", ngx.HTTP_UNAUTHORIZED)    
    end
    
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end


return OidcHandler
