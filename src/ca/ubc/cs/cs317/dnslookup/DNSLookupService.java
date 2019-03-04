package ca.ubc.cs.cs317.dnslookup;
import java.net.DatagramPacket;
import java.io.Console;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

import com.sun.javafx.scene.control.skin.FXVK.Type;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;


public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {
        
        DNSNode usingNode  = node;
        String NAME = usingNode.getHostName();
        if(NAME.substring(NAME.length()-1,NAME.length()).equals(".")){
            usingNode = new DNSNode(NAME.substring(0,NAME.length()-1), usingNode.getType());
        }
        if(NAME.substring(0,1).equals(".")){
            System.err.println("--> "+"'"+ node.getHostName()+"'"+" is not a legal name");
            return Collections.emptySet();
        }
        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

      /*  if(usingNode.getType() == RecordType.CNAME){
            getFromCache(usingNode);
        }*/
    
        
        /*DNSNode newNode = node ;
        String[] domainParts = NAME.split("\\.");
        if (!domainParts[0].equals("www" )&& domainParts.length < 3){
            newNode = new DNSNode(("www." + NAME), node.getType());
        }*/
       /* if (domainParts[0].equals("www")&& domainParts.length > 3){
            newNode = new DNSNode(NAME.substring(NAME.indexOf(".")+1), node.getType());

        }*/
        
        //System.out.println(node1.getHostName()+"      "+node1.getType());


   
        Set<ResourceRecord> setRR = cache.getCachedResults(usingNode);
        try{
        if(setRR.isEmpty()){
            setRR = getFromCache(usingNode);
            InetAddress server = rootServer;
            if(!setRR.isEmpty()){
                server = chooseARecord(setRR).getInetResult();
              //  System.out.println("------------------------>  "+ server);
            }
           // System.out.println("++++++++++++++++++++++++++++>>>  "+ usingNode.getHostName()+"  "+usingNode.getType());
            retrieveResultsFromServer(usingNode, server, indirectionLevel);
            setRR = cache.getCachedResults(usingNode);
        }}catch(StackOverflowError e){

           // System.err.println("---> Too many queries");
        }
     
       
        return setRR;
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server, int indirectionLevel) {
 /*  System.out.println("before------------------------>:node    "+node.getHostName());
        System.out.println("before------------------------>:node    "+node.getType());
        System.out.println("before------------------------>:RRname    "+resourceRecord.getHostName());
        System.out.println("before------------------------>:RRInet    "+resourceRecord.getInetResult());
        System.out.println("before------------------------>:RRType    "+resourceRecord.getType());
        */
        //System.out.println("\n \n \n");
        //System.out.println("\n \n \n");

        //System.out.println("-------------------------------------------------------------------------------------------");

        DNSQuery dnsQuery = new DNSQuery(socket , node, server, 0, 0, verboseTracing);

        
        if(dnsQuery.answer.AA == 1 || dnsQuery.answer.ANCOUNT > 0){
            if(dnsQuery.answer.cname == 1){
                resolveCname(node, node, indirectionLevel);
            }
            return;}
        ResourceRecord newRR = dnsQuery.getServerToSendTo();
        InetAddress nextServer =newRR.getInetResult();
        if(newRR.getType() == RecordType.NS || newRR.getType() == RecordType.CNAME){
            DNSNode newNode = new DNSNode(newRR.getTextResult(), RecordType.A);
            Set<ResourceRecord> set = getResults(newNode, 0);
            //System.out.println("------------->:  "+newRR.getHostName()+"  "+newRR.getInetResult()+"  "+newRR.getTextResult());
            if(!set.isEmpty()){
             nextServer = chooseARecord(set).getInetResult();
                //System.out.println("------------->:  "+newRR.getHostName()+"  "+nextServer);
            }
        }
     
        //System.out.println("DEB UGIMN DEBUGINH------------->>>>    "+ node.getHostName()+"   "+nextServer+"  "+ node.getType()+"  ");


        retrieveResultsFromServer(node, nextServer, indirectionLevel);
    

    }

    

    private static void resolveCname(DNSNode node, DNSNode node2, int indirectionLevel){
        
       DNSNode cnamNode = new DNSNode(node2.getHostName(), RecordType.CNAME);
       

        //getResults(cnamNode, 0);

            String hostName = chooseARecord(cache.getCachedResults(cnamNode)).getTextResult();
            DNSNode nodia = new DNSNode(hostName, node.getType());
            DNSNode nodibi = new DNSNode(hostName, RecordType.CNAME);
            Set<ResourceRecord> setRR = cache.getCachedResults(nodia);
            Set<ResourceRecord> setRR2 = cache.getCachedResults(nodibi);
            if(!setRR.isEmpty()){
                for(ResourceRecord RR: setRR){
                ResourceRecord solvedCnameRR =  new ResourceRecord(node.getHostName(),node.getType(), 
                RR.getTTL(), RR.getInetResult());
                cache.addResult(solvedCnameRR);}
                return;
            }
            else if(!setRR2.isEmpty()){
                //ResourceRecord RR = chooseARecord(setRR);
                resolveCname(node, nodibi, indirectionLevel);
                
            }else{
                DNSNode newNode = new DNSNode(hostName, node.getType());
                //System.out.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                getResults(newNode, indirectionLevel+1);
                resolveCname(node, node, indirectionLevel);

            }
        
        

    }

    private static Set<ResourceRecord> getFromCache(DNSNode node){
        //System.out.println("ZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻZZZZZŹZŻ");
        String name = node.getHostName();
        String[] domainParts = name.split("\\.");
    
        if((domainParts[0].substring(0).equals("w") && domainParts.length == 2) || 
        domainParts.length ==1){
            return Collections.emptySet();
        }
        else if(domainParts[0].substring(0,1).equals("w") && domainParts.length > 2){
            name = name.substring(name.indexOf(".")+1);
            name = name.substring(name.indexOf(".")+1);
            //System.out.println("========> "+name );
            return getFromCacheHelper(new DNSNode(name, node.getType()));
        }
        else{
        name = name.substring(name.indexOf(".")+1);
        DNSNode newNode = new DNSNode(name, node.getType());            
        //System.out.println("pp========> "+name );
        return getFromCacheHelper(newNode);


        }
       


    }

    private static Set<ResourceRecord> getFromCacheHelper(DNSNode node){
        //System.out.println("PLPLPLPLPLPLLPLLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLPLP");
        String name = node.getHostName();
        String[] domainParts = name.split("\\.");
        Set<ResourceRecord> setRR = cache.getCachedResults(node);
        Set<ResourceRecord> setRRNS = cache.getCachedResults(
            new DNSNode(name, RecordType.NS));
        DNSNode newNode = new 
        DNSNode(node.getHostName().substring(name.indexOf(".")+1), node.getType());
    
        if (!setRR.isEmpty()){
                return setRR;
        }
        if(!setRRNS.isEmpty()){
            //System.out.println("HELLLLLLOOOOOO WORLLDLDLLDLDDLLD");
            return resolveNSCache(node, node);
        }
        if(domainParts.length ==1){
            return Collections.emptySet();
        }

        return getFromCacheHelper(newNode);

    }


    private static Set<ResourceRecord> resolveNSCache(DNSNode node, DNSNode node2){
        DNSNode NSNode = new DNSNode(node2.getHostName(), RecordType.NS);
    
             String hostName = chooseARecord(cache.getCachedResults(NSNode)).getTextResult();
             DNSNode nodia = new DNSNode(hostName, node.getType());
             DNSNode nodibi = new DNSNode(hostName, RecordType.NS);
             Set<ResourceRecord> setRR = cache.getCachedResults(nodia);
             Set<ResourceRecord> setRR2 = cache.getCachedResults(nodibi);
             if(!setRR.isEmpty()){
                return setRR;
             }
             else if(!setRR2.isEmpty()){
                 //ResourceRecord RR = chooseARecord(setRR);
                 return resolveNSCache(node, nodibi);
                 
             }else{

                return Collections.emptySet();
             }
     }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
        

    }


    private static ResourceRecord chooseARecord(Set<ResourceRecord> set){
        ResourceRecord tempRR = null;
        if(!set.isEmpty()){
        int size = set.size();
        int item = new Random().nextInt(size); 
        int i = 0;
        for(ResourceRecord obj : set)
        {
            if (i == item){
                tempRR = obj;
                
            }
            i++;
        }}
        
        return tempRR;


    }
    /**
     * Send the DNSQuery ti the 
     */

   
}
