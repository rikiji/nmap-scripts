description = [[
      Looks for text editor backups and swap files of CMS configuration files, e.g. "wp-config.php~"
]]

---
-- @usage
-- nmap --script=http-config-backup <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-config-backup: 
-- |   http://example.com/wp-config.php~
-- |   http://example.com/#wp-config.php#
-- |   http://example.com/wp-config.php.1
-- |_  http://example.com/config copy.php
--
-- @args http-config-backup.base the path where the CMS is installed
-- @args http-config-backup.save save all the valid config files found
--

author = "Riccardo Cecolin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'http'
require 'shortport'
require 'url'

portrule = shortport.http

---
--Creates combinations of backup names for a given filename
--Taken from: http-backup-finder.nse
local function backupNames(filename)
   local function createBackupNames()
      local dir = filename:match("^(.*/)") or ""
      local basename, suffix = filename:match("([^/]*)%.(.*)$")
      
      local backup_names = {}
      if basename then
	 table.insert(backup_names, "{basename}.bak") -- generic bak file
      end
      if basename and suffix then 
	 table.insert(backup_names, "{basename}.{suffix}~") -- vim, gedit
	 table.insert(backup_names, "#{basename}.{suffix}#") -- emacs
	 table.insert(backup_names, "{basename} copy.{suffix}") -- mac copy
	 table.insert(backup_names, "Copy of {basename}.{suffix}") -- windows copy
	 table.insert(backup_names, "Copy (2) of {basename}.{suffix}") -- windows second copy
	 table.insert(backup_names, "{basename}.{suffix}.1") -- generic backup
	 table.insert(backup_names, "{basename}.{suffix}.save") -- nano
	 table.insert(backup_names, "{basename}.{suffix}.swp") -- vim swap
	 table.insert(backup_names, "{basename}.{suffix}.old") -- generic backup
      end
      
      local replace_patterns = {
	 ["{filename}"] = filename,
	 ["{basename}"] = basename,
	 ["{suffix}"] = suffix,
      }

      for _, name in ipairs(backup_names) do
	 local backup_name = name
	 for p, v in pairs(replace_patterns) do
	    backup_name = backup_name:gsub(p,v)
	 end
	 coroutine.yield(dir .. backup_name)
      end
   end
   return coroutine.wrap(createBackupNames)
end

---
--Writes string to file
--Taken from: hostmap.nse
-- @param filename Filename to write
-- @param contents Content of file
-- @return True if file was written successfully
local function write_file(filename, contents)
  local f, err = io.open(filename, "w")
  if not f then
    return f, err
  end
  f:write(contents)
  f:close()
  return true
end

encode = function (val)
	    -- escape just the needed characters
	    local patterns = {
	       ["#"] = "%23",
	       [" "] = "%20"
	    }
	    return patterns[val]
	 end

action = function(host, port)
	    
	    local configs = { 
	       ["wp-config.php"] = "<?php", -- WordPress
	       ["config.php"] = "<?php", -- phpBB, ExpressionEngine
	       ["configuration.php"] = "<?php", -- Joomla
	       ["LocalSettings.php"] = "<?php", -- MediaWiki
	       ["mt-config.cgi"] = "CGIPath", -- Movable Type
	       ["settings.php"] = "<?php",  -- Drupal
	    }
	    
	    local backups = {}

	    local base = stdnse.get_script_args("http-config-backup.base")

	    if not base then
	       base = "/"
	    end

	    local save = stdnse.get_script_args("http-config-backup.save")

	    if not base:match("^/") then base = "/".. base end
	    if not base:match("/$") then base = base .."/" end
	    	    
	    -- for each config file
	    for cfg, regx in pairs(configs) do
	       -- for each alteration of the filename
	       for entry in backupNames(cfg) do
		  local path = base .. entry
		  local escaped_path = path:gsub("[ #]", encode)
		  
		  -- http request
		  local response = http.get(host, port, escaped_path)
		  
		  if ( response.status == 200 ) then
		     -- check it if is valid before inserting
		     if response.body:match(regx) then
			local filename = ((host.targetname or host.ip) .. path):gsub("/","-")

			-- save the content
			if save then
			   local status, err = write_file(filename, response.body)
			   if status then
			      stdnse.print_debug(1,"%s saved", filename)
			   else
			      stdnse.print_debug(1,"error saving %s", err)
			   end
			end			
			
			table.insert(backups, ("http://%s%s"):format(host.targetname or host.ip, path))
		     else
			stdnse.print_debug(1, "found but not matching: http://%s%s", host.targetname or host.ip, path)
		     end
		  end
	       end
	    end
	    if ( #backups > 0 ) then
	       return stdnse.format_output(true, backups)
	    end
	 end
