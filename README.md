##  Autorecon to Obsidian

Designed to be used with the **Obsidian vault template**, [https://github.com/Hacker-Hermanos/Knowledge-Management-for-Offensive-Security-Professionals].

### Dependencies

- Requires [https://github.com/ncrocfer/whatportis/tree/master/whatportis] to be installed and running in server mode listening on a ip:port (aka loopback)
- For the "fancy" formatting to be rendered properly, several obsidian plugins are needed. Which are included in the mentioned Obisidian vault template above.
- autorecon
- Obsidian

### Instructions

1. Once autorecon finishes running, there will be a "reports" directory in the output directory that autorecon creates. This is the first positional argument of the autorecon2obsidian.py tool.
2. The second positional argument is the absolute path to the root directory of your obsidian vault.
3. A platform ('HTB, 'PG', 'PEN200') must be specified with the "--platform" option.
4. The machines name must be specified with the "--name" parameter.
5. the "whatportis" host and port must be specified with "--host" and "--port"

![](https://i.imgur.com/hp6YmFZ.png)


### Note Generation (All Automatically Generated from the Autorecon output)

![](https://i.imgur.com/FHS7m5b.png)

![](https://i.imgur.com/nbPbRDc.png)

![](https://i.imgur.com/ncJQtfK.png)

![](https://i.imgur.com/b2oLCo5.png)

![](https://i.imgur.com/hINL41o.png)

![](https://i.imgur.com/Br6WBOl.png)
