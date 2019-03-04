package ca.ubc.cs.cs317.dnslookup;
import java.net.DatagramPacket;
import java.io.Console;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;




public class DNSQuery{
    private static final int DEFAULT_DNS_PORT = 53;
    private static boolean verboseTracing;
    public static InetAddress recievServer;
    public DNSNode nodeQueried;
    public short ID;
    public int QR = 0;
    public short Opcode = 0;
    public int RD;
    public short QDCOUNT = 1;
    final byte z = 0;
    public short AA = 0;
    public short TC = 0;
    public short RA = 0;
    private static Random random = new Random();
    public short ANCOUNT = 0;
    public short NSCOUNT = 0;
    public short ARCOUNT = 0;
    public short QTYPE = 2;
    public short QCLASS = 1;
    public DNSResponse answer;
    DNSCache cache = DNSCache.getInstance();


    public DNSQuery(DatagramSocket socket, DNSNode node, InetAddress server, int OPCODE, int RD, boolean verbose){
        this.ID = (short) random.nextInt(Short.MAX_VALUE + 1);
        this.QR = (short) this.QR << 15;
        this.RD = RD << 8;
        this.QTYPE = (short) node.getType().getCode();
        this.nodeQueried = node;
        recievServer = server;
        verboseTracing = verbose;

        MakeDNSQuery(socket, node, server);
      

    }

    public void printResults(){
        for(ResourceRecord RR: this.answer.resourceList ){
            System.out.println(RR.getHostName()+"       ,  "+ RR.getType()+"     ,  "+ RR.getInetResult());

        }


    }


    public void verbosePrintResourceRecord(){
        ArrayList<ResourceRecord> nsResource = new ArrayList<ResourceRecord>();
        ArrayList<ResourceRecord> aResource = new ArrayList<ResourceRecord>();
        ArrayList<ResourceRecord> adResource = new ArrayList<ResourceRecord>();
        int nscount = 0;
        int adCount = 0;
        String Server = recievServer.toString();
        System.out.println("\n\n\n");
        System.out.println(" Query ID      "+ this.ID +" "+ nodeQueried.getHostName() 
        +"  "+nodeQueried.getType()+ " -->  "+ Server.substring(1,Server.length()));
        System.out.println(" Response ID:  "+ this.ID +" "+ "Authoritative = "+ (answer.AA == 1));
        for(ResourceRecord RR: answer.resourceList){
            if(RR.getType() == RecordType.NS){
                nscount++;  
                nsResource.add(RR);
            }else if(RR.getNode().equals(nodeQueried)){
                aResource.add(RR);
                if(answer.ANCOUNT < aResource.size())
                    answer.ANCOUNT++;
            }
            else{
                adResource.add(RR);
            }
              
        }
        adCount = answer.resourceList.size()-nscount - answer.ANCOUNT;
        System.out.println("    Answers ("+ answer.ANCOUNT +")");
        for(ResourceRecord RR: aResource){
            verbosePrintResourceRecord( RR, 0);}
        System.out.println("    Nameservers ("+ nscount +")");
        for(ResourceRecord RR: nsResource){
            verbosePrintResourceRecord( RR, 0);
        }
        System.out.println("    Additional Information ("+ adCount +")");
        for(ResourceRecord RR: adResource){
            verbosePrintResourceRecord( RR, 0);
            }
    }
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                record.getTTL(),
                record.getType() == RecordType.OTHER ? rtype : record.getType(),
                record.getTextResult());
        }

    public ResourceRecord getServerToSendTo(){
        ResourceRecord RRb = new ResourceRecord(".", RecordType.A, 1000, recievServer);
        //RecordType DesiredType = RecordType.NS;
        RecordType DesiredType2 = RecordType.SOA;
        if (answer.ARCOUNT == 0 && answer.NSCOUNT > 0 && answer.ANCOUNT == 0){
            
            return answer.resourceList.get(0);}
        RecordType DesiredType = RecordType.A;
        //}
        for(ResourceRecord RR: this.answer.resourceList ){
            if (RR.getType() == DesiredType || RR.getType() == DesiredType2 || 
            RR.getType() == RecordType.CNAME){
                return RR;

            }
        }
         return RRb;

    }


    public void MakeDNSQuery(DatagramSocket socket, DNSNode node,InetAddress server){
       try{  
       

     short flag = (short) (((short) QR) ^ Opcode ^ AA ^ TC ^ RD ^ RA ^ z);
     
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // to how the Identifier field is used in many of the ICMP message types.
        dos.writeShort(this.ID);
        dos.writeShort(flag);
        dos.writeShort(QDCOUNT);
        dos.writeShort(ANCOUNT);
        dos.writeShort(NSCOUNT);
        dos.writeShort(ARCOUNT);

        String[] domainParts = node.getHostName().split("\\.");
        //System.out.println(node.getHostName() + " has " + domainParts.length + " parts");
       /* if (domainParts.length > 3){
            String name = node.getHostName().substring(node.getHostName().indexOf(".")+1);
            domainParts = name.split("\\.");
        }*/
        for (int i = 0; i<domainParts.length; i++) {
            //System.out.println("Writing: " + domainParts[i]);
            byte[] domainBytes = domainParts[i].getBytes("UTF-8");
            dos.writeByte(domainBytes.length);
            dos.write(domainBytes);
        }
        dos.writeByte(0x00);

        dos.writeShort(QTYPE);
        dos.writeShort(QCLASS);

        byte[] dnsFrame = baos.toByteArray();
/*
        for (int i = 0; i < dnsFrame.length; i++) {
            System.out.print(", "+i+": 0x" + String.format("%x", dnsFrame[i]) + " " );
        }
        System.out.println("\n");
*/
        //System.out.println("\n");
        // *** Send DNS Request Frame ***
         socket = new DatagramSocket();
        DatagramPacket dnsReqPacket = new DatagramPacket(dnsFrame, dnsFrame.length, server, DEFAULT_DNS_PORT);
        socket.send(dnsReqPacket);
        // Await response from DNS server
        FetchDNSResponse(socket);

        
        

    }catch(IOException e){
        System.out.println("Exception Caught from ID");
        e.printStackTrace();
    }

    }

    


public void FetchDNSResponse(DatagramSocket socket){
        try{

        this.answer = new DNSResponse(); 
        byte[] buf = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);

        /*
        for (int i = 0; i < packet.getLength(); i++) {
            System.out.print(", "+i+": 0x" + String.format("%x", buf[i]) + " " );
        }
        System.out.println("\n");*/

        DataInputStream din = new DataInputStream(new ByteArrayInputStream(buf));
        short ID = din.readShort();
        answer.ID = ID;
        short Flag = din.readShort();
        answer.Flag = Flag;
        answer.AA = (byte) ((Flag & 0x0400) >> 10);
        answer.TC = (byte) ((Flag & 0x0200) >> 9);
        answer.RA = (byte) ((Flag & 0x0080) >> 7);
        this.QDCOUNT = din.readShort();
        answer.ANCOUNT = din.readShort();
        answer.NSCOUNT = din.readShort();
        answer.ARCOUNT = din.readShort();

        if (!checkMatchID(answer)){
            throw new Exception();
        }
    //answer.testPrint1();
    //System.out.println("QDCOUNT: " + String.format("%d",  this.QDCOUNT));

    answer.getResourceRecords(din, buf);

    }catch(IOException e){

    System.out.println("Exception Caught from IO type");}
    catch(Exception e){

        System.out.println("Exception Caught from IO type");
        e.printStackTrace();
    }



}


public boolean checkMatchID(DNSResponse answer){
        return (answer.ID == this.ID);

    }


    

/** HERE IS A CLASS DEDICATED TO Storing THE RESPONSES 
 *   got from the DNS query.
 * 
*/

  

class DNSResponse {
    public short ID;
    public short Flag;
    public byte AA;
    public byte RA;
    public byte TC;
    public short RCODE;
    public short ANCOUNT;
    public short NSCOUNT;
    public short ARCOUNT;
    public int cname;
    ArrayList<ResourceRecord> resourceList = new ArrayList<ResourceRecord>();
  


    public void testPrint1(){
        System.out.println("ID: 0x" + String.format("%x",ID));
        System.out.println("Flags: 0x" + String.format("%x", Flag));
        System.out.println("AA: 0x" + String.format("%x", AA));
        System.out.println("RA: 0x" + String.format("%x", RA));
        System.out.println("TC: 0x" + String.format("%x", TC));
        System.out.println("ANCOUNT: " + String.format("%d", ANCOUNT));
        System.out.println("NSCOUNT: " + String.format("%d", NSCOUNT));
        System.out.println("ARCOUNT: " + String.format("%d", ARCOUNT));

    }
 /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param din the buf stored in DataInputStream format.
     * @param buf array of bytes holding the response.
     */

    public void getResourceRecords(DataInputStream din, byte[] buf){
        int currAddress = 12;
        try{int recLen = 0;
        while ((recLen = din.readByte()) > 0) {
            byte[] record = new byte[recLen];
            currAddress++;
            currAddress += recLen;
            for (int i = 0; i < recLen; i++) {
                record[i] = din.readByte();
            }

        }
        currAddress++;
        short Recordtype = din.readShort();
        short RecordClass = din.readShort();
    
        currAddress += 4;
   
    getResourceRecordsHelper(din, buf, currAddress);

}catch(IOException exception){
    System.out.println("EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS 1");

    
}


    }

    public void getResourceRecordsHelper(DataInputStream din, byte[] buf, int currAddress){

    while( currAddress<buf.length-1 && buf[currAddress] != 0x0){
        try{ short NamePointer = din.readShort();
        short Type = din.readShort();
        RecordType type = RecordType.getByCode(Type);
        short Class = din.readShort();
        int TTL = din.readInt();
        long ttl = (int) TTL;
        short RDLENGTH = din.readShort();
        ResourceRecord dNSRecord;
        currAddress += 12;

        advanceRDATA(din, RDLENGTH);
        
        int pointer = (int) (NamePointer & 0x03FF);

        String hostName = fetchName(buf, pointer, RecordType.NS, RDLENGTH);
        if(!hostName.isEmpty())
            hostName = hostName.substring(1, hostName.length());
        String inetAdd = fetchName(buf, currAddress, type, RDLENGTH);

        currAddress += RDLENGTH;
        if(type == RecordType.NS || type == RecordType.CNAME){
            inetAdd = inetAdd.substring(1,inetAdd.length());
            dNSRecord = new ResourceRecord(hostName, type, TTL, inetAdd);
        }else{
            InetAddress inetAddress = InetAddress.getByName(inetAdd);
            dNSRecord = new ResourceRecord(hostName, type, TTL, inetAddress);
        }
        

        //System.out.println("--------------->    "+ dNSRecord.getHostName() +"     "+ dNSRecord.getType());
        //InetAddress inetAddress = InetAddress.getByName(inetAdd);

        
        resourceList.add(dNSRecord);

        }
        catch(IOException exception){
            System.out.println("EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS 2");
            exception.printStackTrace();

       }

    
    
    }
    cacheResults();
    if(verboseTracing)
        verbosePrintResourceRecord();
}


    public void cacheResults(){
        for(ResourceRecord RR: this.resourceList ){
            if(RR.getType() == RecordType.CNAME){
                this.cname = 1;
            }
            cache.addResult(RR);
        }

    }

    //private resolveCName(RR);

    public String fetchName(byte[] buf, int currAddress, RecordType type, int counter ){

        int c = currAddress;
        String inetAdd = "";
        boolean Break = false;  
        if (type == RecordType.NS || type == RecordType.CNAME){
        while(buf[c] != 0x0){
            if((buf[c] & 0xc0) == 0xc0){
                int modif = 0x00FF &buf[c+1];
                int point1 = (short) ((buf[c] << 8) | modif);
                int point = point1 & 0x03FF;
                inetAdd += fetchName( buf, point, type, 2000);
                Break = true;

            }
            if(Break)
                break; 
               
            if(buf[c] < 33){
                inetAdd += '.';}
            else{
        
                  char  ascci = (char) (buf[c]& 0xFF);
                  inetAdd += ascci;
               
            }
        c++;
        }}

        if (type == RecordType.A){
            for (int i = 0; i < counter ; i++){

                inetAdd +=  String.format("%d", (buf[c + i] & 0xFF)) + ".";
            }
            inetAdd = inetAdd.substring(0,inetAdd.length()-1);


        }
        if(type == RecordType.AAAA){
            for (int i = 0; i < counter; i += 2){
                short part1 = (short) ((buf[c + i] << 8) | 0xFF);
                //System.out.println("Part1 "+ String.format("%x", part1));
                short part2 = (short) (buf[c + i + 1] | 0xFF00); 
                //System.out.println("Part2 "+ String.format("%x", part2));
                inetAdd +=  String.format("%x", ((short) (part1 & part2))) + ":";
            }

            inetAdd = inetAdd.substring(0,inetAdd.length()-1);
        }
    
  
        return inetAdd;
    }


    public void advanceRDATA(DataInputStream din, int length ){
        try{
            for (int i = 0; i < length; i++ ) {
                din.readByte();
            }

        }
        catch(Exception exception){
            System.out.println("EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS EXCEPTIONS 3");


        }

    }

   
}


} 