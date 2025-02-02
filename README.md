# Network Monitorizing System - Communication by Computers/Computers' Networks
Read the "Enunciado" of the project for context
#### To run this project you will need:
- [Python3](https://www.python.org/downloads/)
- Simulated Local Network, this project used a Linux Ubuntu Virtual Machine dedicated to it provided by Univerisdade do Minho [Linux Ubuntu 20.04 LTS with CORE 7.5.2 Simulator](http://marco.uminho.pt/ferramentas/CORE/xubuncore.html)

### Firstly make sure your Core Simulator is running and your config.json matches the Hosts you want to fetch Metrics from
## To start Server, you must access the shell of the Host you intend to use as the Server
```shell
$ python3 server.py
```
## To start Agents, you must access the shell of each Host after starting the Server
or:
```shell
$ python3 agent.py
```

### Developed by
[Pedro Gomes](https://github.com/FkGomesKr)
