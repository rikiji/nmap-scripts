description = [[
Checks if the target is a tor node using the tor network consensus obtained from the directory servers.
]]

-- @usage
-- nmap --script=tor-consensus-checker <target>

-- @output
-- Host script results:
-- | tor-consensus-checker: 
-- |_  127.0.0.1 is a tor node

author = "Riccardo Cecolin"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"external", "safe"}

require "http"
require "stdnse"

hostrule = function() return true end

get_consensus = function()
		   
		   -- from tor-0.2.2.35/src/or/config.c
		   local dirservers = {
		      { ip="128.31.0.39", port="9131" },
		      { ip="86.59.21.38", port="80" },
		      { ip="194.109.206.212", port="80" } ,
		      { ip="82.94.251.203", port="80" } ,
		      { ip="216.224.124.114", port="9030" } ,
		      { ip="212.112.245.170", port="80"} ,
		      { ip="193.23.244.244", port="80"} ,
		      { ip="208.83.223.34", port="443"} ,
		      { ip="213.115.239.118", port="443" }
		   }		   

		   for _, srv in ipairs(dirservers) do
		      -- get consensus
		      response = http.get( srv.ip, srv.port, "/tor/status-vote/current/consensus")

		      if not response.status then
			 stdnse.print_debug( 2, srv.ip .. " connection failed")
		      elseif response.status ~= 200  then
			 stdnse.print_debug( 2, srv.ip .. " http error " .. response.status)
		      else
			 stdnse.print_debug( 2, "consensus retrieved from " .. srv.ip)	       
			 return response.body
		      end		      
		   end		   
		   
		   -- no valid server found
		   return nil
		end

local regexp = "r [^%s]+ [^%s]+ [^%s]+ [%d-]+ [%d:]+ ([%d\.]+) ([%d]+) [%d]*"

action = function(host)
	    
	    local cur = 0
	    local i = 1 
	    local results = {}

	    stdnse.print_debug( 2, "checking if " .. host.ip .. " is a tor relay" )	    
	    local consensus = get_consensus()

	    if not consensus then
	       table.insert(results, "failed to connect to directory servers")   
	       return stdnse.format_output(true, results)
	    else
	       -- parse consensus	       
	       while i do
		  i = string.find(consensus, "\n", cur) 
		  
		  if i then
		     line = consensus:sub(cur,i)		  
		     cur = i + 1
		     
		     local _, _, ip, port = string.find(line,regexp)
		     		     
		     if host.ip == ip then	
			stdnse.print_debug( 2, ip .. " " .. port)
			table.insert(results, ip .. " is a tor node")
			return stdnse.format_output(true, results)
		     end

		  end		  		  
	       end	    
	    end

	    table.insert(results, host.ip .. " not found")   
	    return stdnse.format_output(true, results)
	 end