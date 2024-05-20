-- schema.lua
local typedefs = require "kong.db.schema.typedefs"


return {
  no_consumer = true,
  fields = {
    serverUrl = { type = "string", required = true, default = "http://keycloak-host:8180/auth" },
    realm = { type = "string", required = true, default = "MyDemo" },
    minTimeBetweenJwksRequests = { type = "number", default = 0 },
    resource = { type = "string", required = true, default = "backend-server" },
    secret = { type = "string", required = true },
    publicClient = { type = "boolean", required = true, default = false },
    timeout = { type = "number", default = 10000 },
    keepalive = { type = "number", default = 60000 }, 
  },
}