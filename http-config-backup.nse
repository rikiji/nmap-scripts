description = [[
      Looks for text editor backups and swap files of CMS configuration files. Same backup-names engine as http-backup-finder.nse
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
--

author = "Riccardo Cecolin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'http'
require 'shortport'
require 'url'

portrule = shortport.http

local function backupNames(filename)
   local function createBackupNames()
      local dir = filename:match("^(.*/)") or ""
      local basename, suffix = filename:match("([^/]*)%.(.*)$")
      
      local backup_names = {
	 "{basename}.bak", -- generic bak file
	 "{basename}.{suffix}~", -- vim, gedit
	 "#{basename}.{suffix}#", -- emacs
	 "{basename} copy.{suffix}", -- mac copy
	 "Copy of {basename}.{suffix}", -- windows copy
	 "Copy (2) of {basename}.{suffix}", -- windows second copy of
	 "{basename}.{suffix}.1", -- generic backup
	 "{basename}.{suffix}.save", -- nano
	 "{basename}.{suffix}.swp", -- vim swap
	 "{basename}.{suffix}.old", -- generic backup
      }
      
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
	       "wp-config.php", -- WordPress
	       "config.php", -- phpBB, ExpressionEngine
	       "configuration.php", -- Joomla
	       "LocalSettings.php", -- MediaWiki
	       "mt-config.cgi", -- Movable Type
	       "settings.php", -- Drupal
	    }
	    
	    local backups = {}

	    local base = tostring(stdnse.get_script_args("http-config-backup.base"))
	    if not base then
	       base = "/"
	    end

	    if not base:match("^/") then base = "/".. base end
	    if not base:match("/$") then base = base .."/" end
	    	    
	    -- for each config file
	    for _, cfg in ipairs(configs) do
	       -- for each alteration of the filename
	       for entry in backupNames(cfg) do
		  local path = base .. entry
		  local escaped_path = path:gsub("[ #]", encode)
		  
		  -- head http request
		  local response = http.head(host, port, escaped_path)
		  
		  if ( response.status == 200 ) then
		     table.insert(backups, ("http://%s%s"):format(host.targetname or host.ip, path))
		  end
	       end
	    end
	    if ( #backups > 0 ) then
	       return stdnse.format_output(true, backups)
	    end
	 end