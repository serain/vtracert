## vtracert

"Visual" implementation of traceroute. Traces the geographical location of each node and generates KML files readable by Google Earth/Maps, Marble or any other KML reader.

Each node is probed multiple times, giving a more accurate route than traceroute.

#### python vtracert.py -h
```
      _                       _   
 __ _| |_ _ _ __ _ __ ___ _ _| |_ 
 \ V /  _| '_/ _` / _/ -_) '_|  _|
  \_/ \__|_| \__,_\__\___|_|  \__|
           alexkaskasoli(1204925)

usage: vtracert [-h] -d DESTINATION [-o OUTPUT] [-n N_PROBES] [-t MAX_TTL]
                [-lM | -lG]

optional arguments:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        Destination host to trace
  -o OUTPUT, --output OUTPUT
                        Output KML
  -n N_PROBES, --n-probes N_PROBES
                        Number of probes to use for each node
  -t MAX_TTL, --max-ttl MAX_TTL
                        Maximum TTL to reach destination
  -lM, --launch-marble  Launch Marble
  -lG, --launch-google  Launch Google Earth
```
