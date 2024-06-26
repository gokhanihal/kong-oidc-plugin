-- Copyright (C) Kong Inc.
local ffi = require "ffi"
local cjson_safe = require "cjson.safe"
local system_constants = require "lua_system_constants"
local basic_serializer = require "kong.plugins.file-log-atez.basic"

local cjson_encode = cjson_safe.encode

local ngx_timer = ngx.timer.at
local O_CREAT = system_constants.O_CREAT()
local O_WRONLY = system_constants.O_WRONLY()
local O_APPEND = system_constants.O_APPEND()
local S_IRUSR = system_constants.S_IRUSR()
local S_IWUSR = system_constants.S_IWUSR()
local S_IRGRP = system_constants.S_IRGRP()
local S_IROTH = system_constants.S_IROTH()

local oflags = bit.bor(O_WRONLY, O_CREAT, O_APPEND)
local mode = bit.bor(S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH)


ffi.cdef[[
int write(int fd, const void * ptr, int numbytes);
]]

-- fd tracking utility functions
local file_descriptors = {}

-- Log to a file. Function used as callback from an nginx timer.
-- @param `premature` see OpenResty `ngx.timer.at()`
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
local function log(premature, conf, message)
  if premature then
    return
  end

  local msg = "\n\n" .. cjson_encode(message) .. "\n"

  local fd = file_descriptors[conf.path]

  if fd and conf.reopen then
    -- close fd, we do this here, to make sure a previously cached fd also
    -- gets closed upon dynamic changes of the configuration
    ffi.C.close(fd)
    file_descriptors[conf.path] = nil
    fd = nil
  end

  if not fd then
    fd = ffi.C.open(conf.path, oflags, mode)
    if fd < 0 then
      local errno = ffi.errno()
      ngx.log(ngx.ERR, "[file-log] failed to open the file: ", ffi.string(ffi.C.strerror(errno)))
    else
      file_descriptors[conf.path] = fd
    end
  end

  ffi.C.write(fd, msg, #msg)
end

local function get_body_data(conf)
  local req  = ngx.req
  
  if conf.log_body and conf.max_body_size > 0 then                  
    req.read_body()
    local data  = req.get_body_data()    
    if data then
      return string.sub(data, 0, max_body_size)
    end
  
    local file_path = req.get_body_file()
    if file_path then
      local file = io.open(file_path, "r")
      data       = file:read(max_body_size)
      file:close()
      return data
    end
  end
  
  return ""
end

local FileLogHandler = {}

FileLogHandler.PRIORITY = 9
FileLogHandler.VERSION = "2.0.0"

function FileLogHandler:access(conf) 

  ngx.ctx.request_body = ""
  ngx.ctx.response_body = "" 
  if conf.log_body and conf.max_body_size > 0 then
    
    local headers = ngx.req.get_headers()       
    if headers["accept-encoding"] ~="identity" then
      local temp = headers["accept-encoding"]
      ngx.req.set_header("accept-encoding", "identity")
      ngx.req.set_header("accept-encoding-req", temp)
    end
                 
    if headers["content-encoding"] ~="gzip" then
      ngx.ctx.request_body = string.sub(get_body_data(conf), 0, conf.max_body_size)      
    end

    
  end
end

function FileLogHandler:body_filter(conf)    

  if conf.log_body and conf.max_body_size > 0 then

    local headers = ngx.resp.get_headers()
    if (headers["content-encoding"]) ~="gzip" then
      ngx.log(ngx.DEBUG, "================================================================================")
      ngx.log(ngx.DEBUG, "RESPONSE BODY FILE LOG...")
      ngx.log(ngx.DEBUG, "================================================================================")
      ngx.log(ngx.DEBUG, "NGX  arg[1]: " .. cjson_encode(ngx.arg[1]) .. " arg[2]"..cjson_encode(ngx.arg[2]) )  
      ngx.log(ngx.DEBUG, "================================================================================")
      if string.len(ngx.ctx.response_body)<conf.max_body_size then
        local chunk = ngx.arg[1]
        local res_body = ngx.ctx.response_body .. (chunk or "")
        ngx.ctx.response_body = string.sub(res_body, 0, conf.max_body_size)
      end
    end      
  else
    ngx.ctx.request_body = ""
    ngx.ctx.response_body = ""  
  end
  
end

function FileLogHandler:log(conf)
  local message = basic_serializer.serialize(ngx)

  local ok, err = ngx_timer(0, log, conf, message)
  if not ok then
    ngx.log(ngx.ERR, "[file-log] failed to create timer: ", err)
  end

end

return FileLogHandler
