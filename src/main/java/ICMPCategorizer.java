import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;

/**
 * <h1>ICMP Categorizer</h1>
 * ICMPCategorizer utilises the tcpdump commandline tool to categorise packet data into the respective ICMP categories
 * @author Michael Kyeyune
 * @since 2016-04-21
 */
public class ICMPCategorizer
{
    public static void main(String[] args)
    {
        String fileName = "traffic/eth1_eth2_20110208031002";
        String command = "tcpdump";
        ProcessBuilder processBuilder = new ProcessBuilder(command ,"-t", "icmp", "and not src net 192.168.0.0/16", "and not src net 10.0.0.0/8" ,"-r", fileName);
        try
        {
            Process process = processBuilder.start();
            int errorCode = process.waitFor();

            BufferedReader bufferedReader = null;
            String line = null;

            if(errorCode == 0)
            {
                System.out.println("No error occurred");

                //set up the hashmap that does the counting
                HashMap<String, Integer> icmpCategoryMap = new HashMap<String, Integer>();

                bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));

                while((line = bufferedReader.readLine()) != null)
                {
                    //System.out.println(line);

                    //remove message length
                    String tempString = (line.split(","))[0];
                    tempString = tempString.trim();
                    //System.out.println(tempString);

                    //get the icmp message
                    String icmpMessage = (tempString.split(":"))[1];
                    icmpMessage = icmpMessage.trim();
                    //System.out.println(icmpMessage);

                    String icmpCategory = null;

                    if(icmpMessage.contains("unreachable"))
                        icmpCategory = "ICMP Destination unreachable";
                    else
                        icmpCategory = icmpMessage;

                    Integer currentCount = 1;

                    if(icmpCategoryMap.containsKey(icmpCategory))
                    {
                        //increase the count for this icmp category
                        currentCount = icmpCategoryMap.get(icmpCategory);
                        currentCount++;
                    }

                    icmpCategoryMap.put(icmpCategory, currentCount);
                }

                if(icmpCategoryMap.isEmpty())
                    System.out.println("No ICMP data found in file");
                else
                {
                    System.out.println("The tally is as follows:");

                    for (String key: icmpCategoryMap.keySet())
                    {
                        System.out.println(key + " : " + icmpCategoryMap.get(key));
                    }
                }
            }
            else
            {
                System.out.println("An error occurred");
                bufferedReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

                while((line = bufferedReader.readLine()) != null)
                {
                    System.out.println(line);
                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
