import argparse, socket, sys, json, requests, simplekml, subprocess, platform, signal, errno
from html import HTML
from multiprocessing import Pool
from collections import Counter






################################################################################
#                                                                              #
#   GLOBAL CONSTANTS                                                           #
#                                                                              #
################################################################################

MAP_URL = "http://maps.google.com/maps?q="
# Returns JSON object with available information about target IP
GEO_URL = "http://ip-api.com/json/"
# WHOIS link
WHOIS_URL = 'http://whois.domaintools.com/'
# UDP port used for tracing
UDP_PORT = 33434
# For some display bits, we want to know platform
if 'windows' in platform.system().lower(): WINDOWS = True
else: WINDOWS = False
# Application header
HEADER = '''
      _                       _   
 __ _| |_ _ _ __ _ __ ___ _ _| |_ 
 \ V /  _| '_/ _` / _/ -_) '_|  _|
  \_/ \__|_| \__,_\__\___|_|  \__|
           alexkaskasoli(1204925)
'''






################################################################################
#                                                                              #
#   Class: NODE                                                                #
#                                                                              #
#       - Holds information about each node in the route                       #
#                                                                              #
#       - Can be built with only ip, other values will default                 #
#                                                                              #
#       - Uses __str__ magic method for easy printing                          #
#                                                                              #
################################################################################

class Node():
    # Constructor requires only IP, other values optional
    def __init__(self,
                 ip, 
                 host=None,
                 time=None,
                 city=None,
                 country=None,
                 countryCode=None,
                 lat=None,
                 lon=None,
                 region=None,
                 regionName=None):
        self.ip = ip
        self.host = host
        self.time = time
        self.city = city
        self.country = country
        self.countryCode = countryCode
        self.lat = lat
        self.lon = lon
        self.region = region
        self.regionName = regionName

    # Override the __str__ magic function for short and easy printing of node info
    def __str__(self):
        ret_str = ''
        #if self.host: ret_str = self.host
        #else: ret_str = self.ip
        if self.city: ret_str = ret_str+ self.city + ', ' 
        if self.region: ret_str = ret_str + self.region  + ', ' 
        if self.countryCode: ret_str = ret_str + self.countryCode
        return ret_str

    # Returns HTML formatted information about the node
    def html(self, n=None):
        html = HTML()
        if n: html.h3('Node #' + str(n))
        if self.host: 
            html.b(self.host)
            html.b('(' + self.ip + ')')
        else: html.b(self.ip)
        p = html.p('')
        if self.city: p += self.city + ', '
        if self.regionName: p += self.regionName + ', '
        elif self.region: p += self.region + ', '
        if self.country: p += self.country
        html.p
        html.a(WHOIS_URL + self.ip)
        return html






################################################################################
#                                                                              #
#   Function: IP_CHECK()                                                       #
#                                                                              #
#       - Returns True if parameter is a valid IPv4 address                    #
#                                                                              #
################################################################################

def ip_check(ip):
    # Split on dot and make sure we have exactly four bytes
    bytes = ip.split('.')
    if len(bytes) != 4:
        return False
    # Make sure each byte is an int between 0 and 255
    for byte in bytes:
        if not byte.isdigit():
            return False
        i = int(byte)
        if i < 0 or i > 255:
            return False
    return True

### END IP_CHECK() #############################################################



################################################################################
#                                                                              #
#   Function: GET_ARGS()                                                       #
#                                                                              #
#       - Parses and validates command line arguments                          #
#                                                                              #
#       - Returns arguments                                                    #
#                                                                              #
################################################################################

def get_args():
    parser = argparse.ArgumentParser(prog='vtracert')
    # Input file or directory is mandatory
    parser.add_argument('-d', '--destination', required=True, type=str, help='Destination host to trace')
    # Output file or directory
    parser.add_argument('-o', '--output', type=str, default='route.kml', help='Output KML')
    # Number of probes to use when identifying a particular node in the route
    parser.add_argument('-n', '--n-probes', type=int, default=20, help='Number of probes to use for each node')
    # Maximum time-to-live
    parser.add_argument('-t', '--max-ttl', type=int, default=30, help='Maximum TTL to reach destination')
    
    # The launchers are mutually exclusive
    launchers = parser.add_mutually_exclusive_group(required=False)
    # Marble
    launchers.add_argument('-lM', '--launch-marble', action='store_true', help='Launch Marble')
    # Google Earth
    launchers.add_argument('-lG', '--launch-google', action='store_true', help='Launch Google Earth')
    
    # Parse args
    args = parser.parse_args()

    print '\n [ i ] Max TTL set to ' + str(args.max_ttl)
    print '\n [ i ] Using ' + str(args.n_probes) + ' probes for each TTL value'
    print '\n [ i ] Output KML file set to ' + str(args.output)

    if WINDOWS:
        print '\n [ i ] Windows will only allow one process to be bound to each socket\n\n       limiting probes to 1'
        args.n_probes = 1

    # If target is not a valid IPv4 address, try to resolve it
    if not ip_check(args.destination):
        print '\n [ i ] Trying to resolve destination host ' + args.destination
        try:
            ip = socket.gethostbyname(args.destination)
            print '\n [ i ] Host ' + args.destination + ' has been resolved to ' + ip
            args.destination = ip
        except:
            # If we can't resolve, we quit
            print '\n [ i ] Couldn\'t resolve ' + args.destination
            print '\n [ i ] Terminating ' + sys.argv[0]
            sys.exit(1)
        
    print '\n [ i ] Destination set to',
    try:
        print socket.gethostbyaddr(args.destination)[0] + ' (' + args.destination + ')'
    except:
        print args.destination

    return args

### END GET_ARGS() #############################################################



################################################################################
#                                                                              #
#   Function: PROBE( TARGET_IP, TTL )                                          #
#                                                                              #
#       - Sends a UDP packet on UDP_PORT with set TTL                          #
#                                                                              #
#       - Listens for ICMP error response and returns node's address           #
#                                                                              #
#       - Each probe is run in it's own process                                #
#                                                                              #
################################################################################

def probe(params):
    ttl = params[0]
    destination = params[1]
    # Create send and recv sockets
    # Send over UDP
    s_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
    # Receive ICMP
    r_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))

    # Set socket's time to live
    s_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # Bind recv socket to listening port
    r_sock.bind(('', UDP_PORT))
    r_sock.settimeout(1) 

    # Send packet from send socket
    s_sock.sendto('', (destination, UDP_PORT))

    addr = ''
    try:
        # Response is a tuple containing response and another tuple containing address
        # The remote address is the first element of the nested tuple
        addr = r_sock.recvfrom(512)[1][0]
    except: return addr
    finally:
        s_sock.close()
        r_sock.close()

    return addr


### END PROBE() ################################################################



################################################################################
#                                                                              #
#   Function: RESOLVE_NODE( TTL, N_PROBES )                                    #
#                                                                              #
#       - Uses a pool of N_PROBES processes to simultaneously probe the target #
#         node in the route                                                    #
#                                                                              #
#       - Returns the most commonly used node at that point in the route with  #
#         it's percentage                                                      #
#                                                                              #
################################################################################

def get_node(ttl, n_probes):
    # Create a pool of n_probes processes, ie: one process for 
    pool = Pool(processes=n_probes)
    # Launch each pool (note: map takes a list of iterables only, easiest way is
    # then to create a list of n_probes times the same arguments, also only one
    # argument can be passed to the function, so we passe a tuple)
    results = pool.map(probe, [(ttl, args.destination)] * n_probes)
    pool.close()
    return top_node(results)

### END RESOLVE_NODE() #########################################################



################################################################################
#                                                                              #
#   Function: TOP_NODE( NODES )                                                #
#                                                                              #
#       - Returns the most occuring non-null item in the NODES list with it's  #
#         count total                                                          #
#                                                                              #
################################################################################

def top_node(nodes):
    counted = Counter(nodes)
    # most_common() returns a list of tuples (ip, count)
    most_common = counted.most_common()
    return most_common[0]

### END TOP_NODE() #############################################################



################################################################################
#                                                                              #
#   Function: TRACE( DEST )                                                    #
#                                                                              #
#       - Traces the route to destination                                      #
#                                                                              #
#       - Returns a list of Node objects                                       #
#                                                                              #
################################################################################

def trace(dest):
    # Hold all the nodes we find in the traceroute
    nodes = []
    # Keep count of how many nodes we couldn't get
    fail_count = 0
    # Have we reached destination?
    dest_reached = False

    print '\n [ i ] Tracing route...\n'

    # Pretty printing for Linux only
    if WINDOWS: print '   #' + ' ' * 32 + 'HOST (IP)' + ' ' * 31 + '%\n'
    else: print '\033[47m\033[30m' + '   #' + ' ' * 32 + 'HOST (IP)' + ' ' * 31 + '%   ' + '\033[0m\n'

    # For each TTL value we are going to call get_node(ttl, n_probes) which will return the 'top_node' reached at that TTL value
    for ttl in range(1, args.max_ttl + 1):
        result = get_node(ttl, args.n_probes)
        node_ip = result[0]
        node_percent = int(float(result[1]) / args.n_probes * 100)

        # Position in route
        print "%4s." % ttl,

        if len(node_ip) == 0:
            print "%66s" % str('*** Couldn\'t trace ***'),
            fail_count = fail_count + 1
            nodes.append(Node(ip=None))
        else:
            try:
                # gethostbyaddr() returns a triple, the first element is the hostname 
                node_host = socket.gethostbyaddr(node_ip)[0]
                print "%66s" % str(node_host + ' (' + node_ip + ')'),
                # append to list of nodes
                nodes.append(Node(ip=node_ip,host=node_host))
            except:
                print "%66s" % str(node_ip + ' (' + node_ip + ')'),
                # append to list of nodes (no hostname)
                nodes.append(Node(ip=node_ip))
        
        # percentage
        print "%4s" % str(node_percent) + '%'

        if node_ip == args.destination:
            dest_reached = True
            print '\n\t\t [ ! ] Destination reached, breaking...'
            break

    if not dest_reached:
        print '\n [ i ] Destination wasn\'t reached, try increasing max TTL value'

    print '\n [ i ] Traced ' + str(len(nodes)) + ' nodes,',
    if not fail_count: print 'all of the node(s) probed'
    else: print 'failed to trace ' + str(fail_count) + ' node(s) probed'

    return nodes


### END TRACE() ################################################################



################################################################################
#                                                                              #
#   Function: GEOLOCATE_NODES( NODES )                                         #
#                                                                              #
#       - Geolocates all nodes in NODES                                        #
#                                                                              #
#       - Returns list of geolocated nodes                                     #
#                                                                              #
################################################################################

def geolocate_nodes(nodes):
    # The list of geolocated nodes returned
    ret_nodes = []
    # The number of nodes successfully located
    success_count = 0

    print '\n [ i ] Geolocating ' + str(len(nodes)) + ' nodes...\n'

    # Pretty display for Linux only, if it's Windows print out plain old boring line
    if WINDOWS: print '   #' + ' ' * 32 + 'HOST' + ' ' * 31 + '%\n'
    else: print '\033[47m\033[30m' + '   #  HOST' + ' ' * 61 + 'LOCATION ' + '\033[0m\n'

    i = 0
    for node in nodes:
        i = i+1
        if node.ip is None:
            print str("%4s. " % i) + str('*** Was not identified in trace ***')
            ret_nodes.append(node)
            continue
        # Using requests package for easy HTTP requests to a target IP
        req = requests.get(GEO_URL + node.ip)
        # IP-API website answers with a JSON object
        # we use JSON module for easy and clean handling of this object
        json = req.json()
        
        # Make sure it was successful it was successful
        if json['status'] == 'success':
            success_count += 1
            node.city = json['city']
            node.country = json['country']
            node.countryCode = json['countryCode']
            node.lat = json['lat']
            node.lon = json['lon']
            node.region = json['region']
            ret_nodes.append(node)
            if node.host: print str("%4s. " % i) + node.host.ljust(45),
            else: print str("%4s. " % i) + node.ip.ljust(45),
            print "%27s" % str(node)
        else:
            ret_nodes.append(node)
            print str("%4s. " % i) + str('*** Couldn\'t geolocate ***')

    print '\n [ i ] Geolocated ' + str(success_count) + ' nodes (out of ' + str(len(nodes)) + ')'

    return ret_nodes


### END GEOLOCATE_NODES() ######################################################



################################################################################
#                                                                              #
#   Function: EXPORT_KML(NODES)                                                #
#                                                                              #
#       - Generates a KML file plotting the location of each node in NODES     #
#                                                                              #
#       - Outputs to args.output                                               #
#                                                                              #
################################################################################

def export_kml(nodes):
    kml = simplekml.Kml(open=1)
    
    print '\n [ i ] Generating KML file...'

    # "Fill in the holes"
    # Go through the list of nodes once and improvise lat/lon for points that don't have any
    for i in range(0, len(nodes)):
        # Nodes that couldn't be traced
        if not nodes[i].ip:
            # Set the IP to a text that will be displayed
            nodes[i].ip = '*** Could not be traced ***'
            print '\n\t[ i ] Node ' + str(i+1) + ' could not be traced!\n\t      It\'s location will be set to that of the next located node'
            # Find the next located node in the list
            for j in range(i+1, len(nodes)):
                if nodes[j].lat and nodes[j]:
                    nodes[i].lat = nodes[j].lat
                    nodes[i].lon = nodes[j].lon
                    nodes[i].country = 'Not accurately traced and located!'
                    break
            
        # Nodes that couldn't be located
        elif not nodes[i].lat and not nodes[i].lon:
            if nodes[i].host:
                print '\n\t[ i ] ' + nodes[i].host + ' ('+ nodes[i].ip +') could not be located!\n      It\'s location will be set to that of the next geolocated node'
            else:
                print '\n\t[ i ] ' + nodes[i].ip + ' could not be located!\n\t      It\'s location will be set to that of the next located node'      
            # Find the next located node in the list
            for j in range(i+1, len(nodes)):
                if nodes[j].lat and nodes[j]:
                    nodes[i].lat = nodes[j].lat
                    nodes[i].lon = nodes[j].lon
                    nodes[i].country = 'Not accurately located!'
                    break

    # Add points for each node and prepare list of (lat,long) tuple for LineString
    point_list = []
    ttl = 1


    # Create points while aggregating nodes that are at the same locations
    # Also prepare list of points to use for generating the LineString
    print '\n\t[ i ] Aggregating nodes at identical locations...'
    i = 0
    while i < len(nodes):
        # We keep each points location in a list for the LineString
        point_list.append((nodes[i].lon, nodes[i].lat))

        # Set initial point values
        point = kml.newpoint()
        if i == 0: point.name = '#1 (Origin)' 
        elif i == len(nodes)-1: point.name = '#' + str(i + 1) + ' (Destination) ' 
        else: point.name = '#' + str(i + 1) 
        point.description = str(nodes[i].html(i+1))
        point.coords = [(nodes[i].lon, nodes[i].lat)]

        
        # Check if any other points are at this location
        if i < len(nodes)-1 and nodes[i].lat == nodes[i+1].lat and nodes[i].lon == nodes[i+1].lon:
            print '\n\t\t     * Grouping nodes #' + str(i + 1),
            
            # While the following nodes are at the same location, group them
            while i < len(nodes)-1 and nodes[i].lat == nodes[i+1].lat and nodes[i].lon == nodes[i+1].lon:
                i += 1
                point.name += ' - #' + str(i + 1)
                point.description += '\n<br />\n\n' + str(nodes[i].html(i+1))
                print '- #' + str(i + 1),

            print ''

        i += 1


    # Add LineString, an actual line between each node
    linestring = kml.newlinestring()
    linestring.tessellate = 1
    linestring.coords = point_list
    linestring.altitudemode = simplekml.AltitudeMode.relativetoground
    # Set the LineString style
    linestring.extrude = 1
    linestring.style.linestyle.color = simplekml.Color.red 
    linestring.style.linestyle.width = 5

    kml.save(args.output)

    print '\n [ i ] KML saved in ' + args.output

### END EXPORT_KML() ###########################################################



#
#   SIGNAL_HANGLER() FOR CTRL+C CLEAN EXIT
#
def signal_handler(signal, frame):
    sys.exit(0)


################################################################################
#                                                                              #
#   __MAIN__                                                                   #
#                                                                              #
################################################################################

if __name__ == "__main__":
    # Clean exit
    signal.signal(signal.SIGINT, signal_handler)

    print HEADER
    args = get_args()

    # Listening for ICMP requires sudo permissions, if we get a permission error on the trace we clean exit
    try:
        nodes = trace(args.destination)
    except IOError as e:
        if (e[0] == errno.EPERM):
            print '\n [ i ] Error: You do not have the required privileges for this operation'
            sys.exit(1)

    nodes = geolocate_nodes(nodes)
    export_kml(nodes)

    # Launch KML readers
    if args.launch_google:
        print '\n [ i ] Launching Google Earth with ' + args.output
        subprocess.call(['C:\Program Files\Google\Google Earth\client\googleearth.exe', args.output])
    if args.launch_marble: 
        print '\n [ i ] Launching Marble with ' + args.output
        subprocess.call(['marble', 'map', 'earth/schagen1682/schagen1682.dgml', args.output], stderr=subprocess.PIPE)

    print '\n [ i ] All done!'